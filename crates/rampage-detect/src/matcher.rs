//! Evaluating signatures against a loaded image. Every read is bounds-checked, so a malformed or truncated
//! binary can make a condition fail to match but can never panic.
//!
//! Conditions are tested through the [`Image`] trait rather than against [`Binary`] directly. [`Binary`]
//! implements it over its real sections, imports and overlay; the crate's synthetic tests implement it over
//! crafted inputs, which lets the section, import, overlay and entropy paths be unit-tested without forging a
//! whole object file.

use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use rampage_loaders::{Binary, shannon_entropy};

use crate::model::{Condition, Confidence, Detection, Signature, SignatureDb};
use crate::pattern::BytePattern;

/// The facts a signature is tested against: entry-point bytes, the image, named sections, imports and overlay.
pub(crate) trait Image {
    /// The file-backed bytes at the entry point, or `None` when there is no entry or they are unmapped.
    fn entry_bytes(&self, len: usize) -> Option<&[u8]>;
    /// The whole image's bytes, scanned for un-anchored patterns and image-wide needles.
    fn image_bytes(&self) -> &[u8];
    /// Every section in file order: its name and its file-backed bytes (`None` for zero-fill sections).
    fn sections(&self) -> Vec<(&str, Option<&[u8]>)>;
    /// The names of the libraries imported from.
    fn import_libraries(&self) -> Vec<&str>;
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
    let unanchored = Unanchored::scan(image.image_bytes(), db);
    let mut detections: Vec<Detection> = Vec::new();
    for signature in &db.signatures {
        if let Some(detection) = evaluate(image, &unanchored, signature) {
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
fn evaluate(image: &impl Image, unanchored: &Unanchored, signature: &Signature) -> Option<Detection> {
    if signature.conditions.is_empty() {
        return None;
    }
    let mut evidence = Vec::with_capacity(signature.conditions.len());
    for condition in &signature.conditions {
        evidence.push(check(image, unanchored, condition)?);
    }
    let distinctive = signature.conditions.iter().any(Condition::is_distinctive);
    // A single generic signal is tentative; a distinctive one, or several corroborating ones, is strong.
    let strong = !signature.corroborating && (distinctive || signature.conditions.len() >= 2);
    let confidence = if strong { Confidence::Strong } else { Confidence::Tentative };
    Some(Detection { name: signature.name.clone(), kind: signature.kind, confidence, evidence })
}

/// Where every un-anchored pattern in a database first matches the image, found in one pass for all of them.
///
/// Scanning the image once per pattern costs patterns x image size, seconds for a few thousand PeID entries on a
/// megabyte-sized binary. Instead each pattern is keyed by its longest run of fixed bytes; one Aho-Corasick pass
/// finds every occurrence of every key, and the full pattern is verified only there. Patterns with no fully fixed
/// byte (only nibbles) have no key and fall back to a direct scan.
struct Unanchored {
    first: HashMap<*const BytePattern, usize>,
}

impl Unanchored {
    fn scan(data: &[u8], db: &SignatureDb) -> Self {
        let patterns: Vec<&BytePattern> = db
            .signatures
            .iter()
            .flat_map(|signature| &signature.conditions)
            .filter_map(|condition| match condition {
                Condition::Entry { pattern, ep_only: false } => Some(pattern),
                _ => None,
            })
            .collect();
        let mut first = HashMap::new();
        let mut keys: Vec<Vec<u8>> = Vec::new();
        let mut key_index: HashMap<Vec<u8>, usize> = HashMap::new();
        // For each key, the patterns it stands for and the key's offset inside each.
        let mut owners: Vec<Vec<(&BytePattern, usize)>> = Vec::new();
        let mut unkeyed = Vec::new();
        for pattern in patterns {
            let Some((offset, literal)) = pattern.longest_literal() else {
                unkeyed.push(pattern);
                continue;
            };
            let key = *key_index.entry(literal).or_insert_with_key(|literal| {
                keys.push(literal.clone());
                owners.push(Vec::new());
                keys.len() - 1
            });
            owners[key].push((pattern, offset));
        }
        match AhoCorasick::new(&keys) {
            Ok(automaton) => {
                let mut pending: usize = owners.iter().map(Vec::len).sum();
                for found in automaton.find_overlapping_iter(data) {
                    for &(pattern, offset) in &owners[found.pattern().as_usize()] {
                        let id = std::ptr::from_ref(pattern);
                        // Occurrences of one key arrive in order, so the first verified start is the leftmost.
                        if first.contains_key(&id) {
                            continue;
                        }
                        if let Some(start) = found.start().checked_sub(offset)
                            && pattern.matches_at(&data[start..])
                        {
                            first.insert(id, start);
                            pending -= 1;
                        }
                    }
                    if pending == 0 {
                        break;
                    }
                }
            }
            // Building fails only past the automaton's size limits; scanning each pattern directly still works.
            Err(_) => unkeyed.extend(owners.iter().flatten().map(|&(pattern, _)| pattern)),
        }
        for pattern in unkeyed {
            if let Some(start) = pattern.find_in(data) {
                first.insert(std::ptr::from_ref(pattern), start);
            }
        }
        Self { first }
    }

    fn first_match(&self, pattern: &BytePattern) -> Option<usize> {
        self.first.get(&std::ptr::from_ref(pattern)).copied()
    }
}

/// Tests one condition, returning a human-readable evidence line when it holds.
fn check(image: &impl Image, unanchored: &Unanchored, condition: &Condition) -> Option<String> {
    match condition {
        Condition::Entry { pattern, ep_only } => {
            if *ep_only {
                let bytes = image.entry_bytes(pattern.len())?;
                pattern.matches_at(bytes).then(|| format!("entry-point bytes match {}-byte pattern", pattern.len()))
            } else {
                let at = unanchored.first_match(pattern)?;
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
        Condition::ImportLibrary(library) => {
            let wanted = library.to_ascii_lowercase();
            imported_library(image, |name| name.contains(&wanted))
                .map(|name| format!("imports from {name} (matching {library:?})"))
        }
        Condition::VersionedImportLibrary(prefix) => {
            let prefix = prefix.to_ascii_lowercase();
            let versioned = |name: &str| {
                name.strip_prefix(&prefix).is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
            };
            imported_library(image, versioned).map(|name| format!("imports from versioned runtime {name}"))
        }
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

/// The first imported library whose lower-cased name satisfies `test`.
fn imported_library(image: &impl Image, test: impl Fn(&str) -> bool) -> Option<&str> {
    image.import_libraries().into_iter().find(|name| test(&name.to_ascii_lowercase()))
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

/// Folds a new detection into the list, merging it with an existing one for the same tool. A second signature
/// that adds new evidence corroborates the first, so the merged detection is strong even when each alone was
/// tentative.
fn merge(detections: &mut Vec<Detection>, detection: Detection) {
    if let Some(existing) = detections.iter_mut().find(|d| d.name == detection.name) {
        let known = existing.evidence.len();
        for line in detection.evidence {
            if !existing.evidence.contains(&line) {
                existing.evidence.push(line);
            }
        }
        if detection.confidence == Confidence::Strong || existing.evidence.len() > known {
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
        self.sections.iter().map(|section| (section.name.as_str(), self.section_file_bytes(section))).collect()
    }

    fn import_libraries(&self) -> Vec<&str> {
        self.imports.iter().filter_map(|import| import.library.as_deref()).collect()
    }

    fn imports_function(&self, name: &str) -> bool {
        self.imports.iter().any(|import| import.name.eq_ignore_ascii_case(name))
    }

    fn overlay_size(&self) -> Option<u64> {
        self.overlay.map(|overlay| overlay.size)
    }
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
        fn import_libraries(&self) -> Vec<&str> {
            self.libraries.iter().map(String::as_str).collect()
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

    /// Evaluates one signature on its own, as [`identify_image`] would.
    fn evaluate(image: &impl Image, signature: &Signature) -> Option<Detection> {
        let db = SignatureDb::from_signatures(vec![signature.clone()]);
        super::evaluate(image, &Unanchored::scan(image.image_bytes(), &db), &db.signatures[0])
    }

    /// Deterministic noise (xorshift64), so a failure reproduces.
    fn noise(len: usize, mut state: u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn thousands_of_unanchored_patterns_scan_an_image_quickly() {
        let mut image = noise(1536 * 1024, 7);
        // 12-byte patterns with every third byte a wildcard and some nibble wildcards, as PeID entries look.
        let mut texts: Vec<String> = noise(4000 * 12, 8)
            .chunks(12)
            .map(|bytes| {
                let hex = |(i, byte): (usize, &u8)| match i % 6 {
                    2 => "??".to_owned(),
                    5 => format!("{:X}?", byte >> 4),
                    _ => format!("{byte:02X}"),
                };
                bytes.iter().enumerate().map(hex).collect::<Vec<_>>().join(" ")
            })
            .collect();
        // Degenerate shapes: one fixed byte (a candidate almost everywhere) and only fixed nibbles.
        texts.extend(["E8".to_owned(), "?? 4? ?? 5?".to_owned(), "?? ?? 00 00 ?? ??".to_owned()]);
        for (index, at) in [(17, 1000), (3999, image.len() - 12)] {
            let concrete = texts[index].replace('?', "0");
            let bytes: Vec<u8> = concrete.split(' ').map(|hex| u8::from_str_radix(hex, 16).unwrap()).collect();
            image[at..at + 12].copy_from_slice(&bytes);
        }
        let signatures = texts
            .iter()
            .enumerate()
            .map(|(index, text)| {
                let condition = Condition::Entry { pattern: BytePattern::parse(text).unwrap(), ep_only: false };
                Signature::new(&format!("sig{index}"), Kind::Unknown, vec![condition])
            })
            .collect();
        let db = SignatureDb::from_signatures(signatures);
        let fake = Fake { image, ..Fake::default() };

        let started = std::time::Instant::now();
        let detections = identify_image(&fake, &db);
        let elapsed = started.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(10), "took {elapsed:?}");

        let found = |name: &str| detections.iter().find(|d| d.name == name).map(|d| d.evidence.clone());
        assert_eq!(found("sig17"), Some(vec!["pattern found at image offset 0x3e8".to_owned()]));
        let last = format!("pattern found at image offset {:#x}", fake.image.len() - 12);
        assert_eq!(found("sig3999"), Some(vec![last]));
        for (index, text) in texts.iter().enumerate().filter(|(index, _)| index % 250 == 0 || *index >= 4000) {
            let expected = BytePattern::parse(text).unwrap().find_in(&fake.image);
            let reported = found(&format!("sig{index}"));
            assert_eq!(reported, expected.map(|at| vec![format!("pattern found at image offset {at:#x}")]), "{text}");
        }
    }

    #[test]
    fn entry_pattern_with_wildcards_matches_and_rejects_crafted_bytes() {
        let sig = Signature::new("Stub", Kind::Packer, vec![entry("60 BE ?? ?? ?? ??")]);
        let hit = Fake { entry: vec![0x60, 0xbe, 0x11, 0x22, 0x33, 0x44], ..Fake::default() };
        let miss = Fake { entry: vec![0x61, 0xbe, 0x11, 0x22, 0x33, 0x44], ..Fake::default() };
        assert_eq!(evaluate(&hit, &sig).map(|d| d.evidence.len()), Some(1));
        assert!(evaluate(&miss, &sig).is_none());
    }

    #[test]
    fn an_entry_pattern_is_strong_only_with_four_fixed_bytes() {
        let image = Fake { entry: vec![0x61, 0xbe, 0x11, 0x22], ..Fake::default() };
        let confidence = |pattern: &str| {
            let sig = Signature::new("Stub", Kind::Packer, vec![entry(pattern)]);
            evaluate(&image, &sig).unwrap().confidence
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
        let detection = evaluate(&packed, &sig).expect("UPX section match");
        assert_eq!(detection.confidence, Confidence::Strong);
        assert!(evaluate(&plain, &sig).is_none());
    }

    #[test]
    fn any_section_name_matches_either_alternative() {
        let sig = Signature::new(
            "MPRESS",
            Kind::Packer,
            vec![Condition::AnySectionName(vec![".MPRESS1".to_owned(), ".MPRESS2".to_owned()])],
        );
        let hit = Fake::default().with_section(".MPRESS2", &[0x00; 16]);
        assert!(evaluate(&hit, &sig).is_some());
        assert!(evaluate(&Fake::default(), &sig).is_none());
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
        assert!(evaluate(&image, &lib).is_some());
        assert!(evaluate(&image, &func).is_some());
        assert!(evaluate(&Fake::default(), &lib).is_none());
    }

    #[test]
    fn only_versioned_runtimes_mean_msvc() {
        let db = SignatureDb::bundled();
        let msvc = |library: &str| {
            let image = Fake { libraries: vec![library.to_owned(), "KERNEL32.dll".to_owned()], ..Fake::default() };
            identify_image(&image, &db).iter().any(|detection| detection.name == "MSVC")
        };
        assert!(!msvc("msvcrt.dll"), "MinGW and Rust gnu targets import msvcrt.dll");
        assert!(msvc("MSVCR120.dll"));
        assert!(msvc("msvcp140.dll"));
        assert!(msvc("VCRUNTIME140_1.dll"));
    }

    #[test]
    fn overlay_and_entropy_conditions_gate_on_crafted_values() {
        let overlay_sig = Signature::new("Installer", Kind::Installer, vec![Condition::OverlayPresent]);
        let with_overlay = Fake { overlay: Some(4096), ..Fake::default() };
        assert!(evaluate(&with_overlay, &overlay_sig).is_some());
        assert!(evaluate(&Fake::default(), &overlay_sig).is_none());

        // A uniform-random section reaches 8 bits/byte; a run of one value sits at 0.
        let high: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let entropy_sig = Signature::new(
            "Packed",
            Kind::Packer,
            vec![Condition::MinSectionEntropy { section: Some(".text".to_owned()), min: 7.0 }],
        );
        let packed = Fake::default().with_section(".text", &high);
        let plain = Fake::default().with_section(".text", &[0x90; 4096]);
        assert!(evaluate(&packed, &entropy_sig).is_some());
        assert!(evaluate(&plain, &entropy_sig).is_none());
    }

    #[test]
    fn image_wide_needle_matches_anywhere_in_the_image() {
        let sig = Signature::new(
            "NSIS",
            Kind::Installer,
            vec![Condition::SectionContains { section: None, needle: b"NullsoftInst".to_vec() }],
        );
        let image = Fake { image: b"....NullsoftInst0123".to_vec(), ..Fake::default() };
        assert!(evaluate(&image, &sig).is_some());
        assert!(evaluate(&Fake::default(), &sig).is_none());
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
    fn startup_object_gcc_stamps_do_not_make_a_clang_mold_build_strong_gcc() {
        // A Clang build linked by mold against glibc: crt1.o and crti.o bring their own GCC producer strings.
        let comment = b"GCC: (GNU) 13.2.0\0clang version 18.1.0\0mold 2.30.0 (compatible with GNU ld)\0";
        let image = Fake::default().with_section(".comment", comment);
        let detections = identify_image(&image, &SignatureDb::bundled());
        let found = |name: &str| detections.iter().find(|d| d.name == name).map(|d| d.confidence);
        assert_eq!(found("GCC"), Some(Confidence::Tentative));
        assert_eq!(found("Clang/LLVM"), Some(Confidence::Strong));
        assert_eq!(found("mold"), Some(Confidence::Strong));
        assert_eq!(found("GNU ld"), None);
    }

    #[test]
    fn two_independent_tentative_signals_for_one_tool_merge_strong() {
        let image = Fake { overlay: Some(64), ..Fake::default() }.with_section("pec1", &[0u8; 8]);
        let section = Signature::new("PECompact", Kind::Packer, vec![Condition::SectionName("pec1".to_owned())]);
        let overlay = Signature::new("PECompact", Kind::Packer, vec![Condition::OverlayPresent]);
        let merged = identify_image(&image, &SignatureDb::from_signatures(vec![section.clone(), overlay]));
        assert_eq!(merged[0].confidence, Confidence::Strong);
        // A repeat of the same signal is not independent corroboration.
        let repeated = identify_image(&image, &SignatureDb::from_signatures(vec![section.clone(), section]));
        assert_eq!(repeated[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn a_single_generic_section_name_is_only_tentative() {
        let sig = Signature::new("PECompact", Kind::Packer, vec![Condition::SectionName("pec1".to_owned())]);
        let image = Fake::default().with_section("pec1", &[0u8; 8]);
        assert_eq!(evaluate(&image, &sig).unwrap().confidence, Confidence::Tentative);
    }

    #[test]
    fn a_single_tool_branded_section_name_is_strong() {
        let names = vec![".gopclntab".to_owned(), "__gopclntab".to_owned()];
        let sig = Signature::new("Go", Kind::Compiler, vec![Condition::UniqueSectionName(names)]);
        let image = Fake::default().with_section(".gopclntab", &[0u8; 8]);
        let detection = evaluate(&image, &sig).unwrap();
        assert_eq!(detection.confidence, Confidence::Strong);
        assert_eq!(detection.evidence, ["section .gopclntab present"]);
        // Absent names still do not match.
        assert!(evaluate(&Fake::default().with_section(".text", &[0u8; 8]), &sig).is_none());
    }
}
