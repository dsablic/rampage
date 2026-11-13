//! Evaluating signatures against a loaded image. Every read is bounds-checked, so a malformed or truncated
//! binary can make a condition fail to match but can never panic.
//!
//! Conditions are tested through the [`Image`] trait rather than against [`Binary`] directly. [`Binary`]
//! implements it over its real sections, imports and overlay; the crate's synthetic tests implement it over
//! crafted inputs, which lets the section, import, overlay and entropy paths be unit-tested without forging a
//! whole object file.

use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use rampage_loaders::{Binary, Details, Format, shannon_entropy};

use crate::model::{Condition, Confidence, Detection, Signature, SignatureDb};
use crate::pattern::BytePattern;

/// The facts a signature is tested against: entry-point bytes, the image, named sections, imports and overlay.
pub(crate) trait Image {
    /// The container format, when known.
    fn format(&self) -> Option<Format>;
    /// The file-backed bytes at the entry point, or `None` when there is no entry or they are unmapped.
    fn entry_bytes(&self, len: usize) -> Option<&[u8]>;
    /// The whole image's bytes, overlay included, for the image entropy.
    fn image_bytes(&self) -> &[u8];
    /// The image's bytes before its overlay, scanned for un-anchored patterns and image-wide needles: appended
    /// data is not the image's own.
    fn body_bytes(&self) -> &[u8];
    /// The overlay's bytes, when the image has one.
    fn overlay_bytes(&self) -> Option<&[u8]>;
    /// The GUID of the PE debug directory's CodeView record, when there is one.
    fn codeview_guid(&self) -> Option<[u8; 16]>;
    /// Every section in file order: its name and its file-backed bytes (`None` for zero-fill sections).
    fn sections(&self) -> Vec<(&str, Option<&[u8]>)>;
    /// The names of the libraries imported from.
    fn import_libraries(&self) -> Vec<&str>;
    /// Whether any imported function matches `name` (compared case-insensitively).
    fn imports_function(&self, name: &str) -> bool;
    /// The first symbol whose name satisfies `test`.
    fn find_symbol(&self, test: &dyn Fn(&str) -> bool) -> Option<&str>;
    /// The Mach-O build-version tools, as (tool, version) pairs; empty for other formats.
    fn build_tools(&self) -> Vec<(&str, &str)>;
    /// The overlay's size in bytes, when the image has one.
    fn overlay_size(&self) -> Option<u64>;
    /// The entry point's address.
    fn entry(&self) -> Option<u64>;
    /// `len` file-backed bytes at `address`.
    fn read(&self, address: u64, len: usize) -> Option<&[u8]>;
    /// Whether multi-byte values are stored big-endian.
    fn big_endian(&self) -> bool;
    /// The libraries the image links by name: PE import libraries, ELF `DT_NEEDED` entries, Mach-O dylib file
    /// names (the last path component).
    fn linked_libraries(&self) -> Vec<&str>;
    /// The imported functions with the library each comes from, when the format records it.
    fn imported_functions(&self) -> Vec<(Option<&str>, &str)>;
    /// Whether an export has exactly this name.
    fn exports(&self, name: &str) -> bool;
    /// The architecture's pointer width in bits, when known.
    fn pointer_bits(&self) -> Option<u8>;
}

/// Identifies the tools that produced `binary`, testing every signature in `db`. Detections that name the same
/// tool are merged, their evidence pooled, and the result is sorted strongest first, then by name.
pub fn identify(binary: &Binary, db: &SignatureDb) -> Vec<Detection> {
    identify_image(binary, db)
}

pub(crate) fn identify_image(image: &impl Image, db: &SignatureDb) -> Vec<Detection> {
    let unanchored = Unanchored::scan(image.body_bytes(), db);
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
        let line = check(image, unanchored, condition)?;
        // A format only narrows the match; the evidence is what was found within it.
        if !matches!(condition, Condition::Format(_)) {
            evidence.push(line);
        }
    }
    // A format pins where unscoped searches may count, but is no signal of its own.
    let pinned = signature.conditions.iter().any(|condition| matches!(condition, Condition::Format(_)));
    let signals = signature.conditions.iter().filter(|condition| !matches!(condition, Condition::Format(_)));
    let distinctive =
        signals.clone().any(|condition| condition.is_distinctive() && (pinned || !condition.is_unscoped()));
    // A single generic signal is tentative; a distinctive one, or several corroborating ones, is strong. Unscoped
    // searches of a signature that names no format are generic however distinctive their bytes.
    let strong = !signature.corroborating && (distinctive || signals.count() >= 2);
    let confidence = if strong { Confidence::Strong } else { Confidence::Tentative };
    if let Some(origin) = &signature.origin {
        for line in &mut evidence {
            *line = format!("{origin}: {line}");
        }
    }
    Some(Detection {
        name: signature.name.clone(),
        kind: signature.kind,
        confidence,
        evidence,
        sources: vec![signature.source],
        versions: signature.version.iter().cloned().collect(),
    })
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
        Condition::Format(format) => (image.format() == Some(*format)).then(String::new),
        Condition::Entry { pattern, ep_only } => {
            if *ep_only {
                let bytes = image.entry_bytes(pattern.len())?;
                pattern.matches_at(bytes).then(|| format!("entry-point bytes match {}-byte pattern", pattern.len()))
            } else {
                let at = unanchored.first_match(pattern)?;
                Some(format!("pattern found at image offset {at:#x}"))
            }
        }
        Condition::EntryJumps(pattern) => {
            let entry = image.entry()?;
            pattern
                .matches_from(entry, image.big_endian(), |address, len| image.read(address, len).map(<[u8]>::to_vec))
                .then(|| "entry-point code matches a pattern that follows its jumps".to_owned())
        }
        Condition::FileBytes { offset, pattern } => {
            let start = usize::try_from(*offset).ok()?;
            let bytes = image.image_bytes().get(start..)?;
            pattern.matches_at(bytes).then(|| format!("file bytes at offset {offset:#x} match {}-byte pattern", pattern.len()))
        }
        Condition::OverlayBytes(pattern) => pattern
            .matches_at(image.overlay_bytes()?)
            .then(|| format!("overlay starts with {}-byte pattern", pattern.len())),
        Condition::Library(name) => {
            let pe = image.format() == Some(Format::Pe);
            image
                .linked_libraries()
                .into_iter()
                .find(|linked| if pe { linked.eq_ignore_ascii_case(name) } else { linked == name })
                .map(|linked| format!("links library {linked}"))
        }
        Condition::ImportedFunction { library, name } => image
            .imported_functions()
            .into_iter()
            .find(|(from, function)| {
                function == name
                    && library.as_ref().is_none_or(|wanted| from.is_some_and(|from| from.eq_ignore_ascii_case(wanted)))
            })
            .map(|(from, function)| match from {
                Some(from) => format!("imports function {function} from {from}"),
                None => format!("imports function {function}"),
            }),
        Condition::Export(name) => image.exports(name).then(|| format!("exports {name}")),
        Condition::PointerBits(bits) => {
            (image.pointer_bits() == Some(*bits)).then(|| format!("{bits}-bit image"))
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
            None => contains(image.body_bytes(), needle).then(|| format!("image contains {:?}", preview(needle))),
        },
        Condition::DebugContains(needle) => {
            let prefix = if image.format() == Some(Format::MachO) { "__debug_" } else { ".debug_" };
            image
                .sections()
                .into_iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .find(|(_, bytes)| bytes.is_some_and(|bytes| contains(bytes, needle)))
                .map(|(name, _)| format!("debug section {name} contains {:?}", preview(needle)))
        }
        Condition::OverlayContains(needle) => {
            contains(image.overlay_bytes()?, needle).then(|| format!("overlay contains {:?}", preview(needle)))
        }
        Condition::CodeViewGuid(pattern) => {
            let guid = image.codeview_guid()?;
            pattern.matches_at(&guid).then(|| format!("CodeView record GUID {} matches", hex(&guid)))
        }
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
        Condition::BuildTool(wanted) => image
            .build_tools()
            .into_iter()
            .find(|(tool, _)| tool == wanted)
            .map(|(tool, version)| format!("LC_BUILD_VERSION records {tool} {version}")),
        Condition::Symbol(name) => image
            .find_symbol(&|symbol| source_name(image, symbol) == name)
            .map(|symbol| format!("symbol {symbol} present")),
        Condition::SymbolPrefix(prefix) => image
            .find_symbol(&|symbol| {
                let symbol = source_name(image, symbol);
                symbol.len() > prefix.len() && symbol.starts_with(prefix.as_str())
            })
            .map(|symbol| format!("symbol {symbol} (prefix {prefix})")),
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

/// A symbol's name as the source spelled it: Mach-O prefixes every C-level name with one underscore
/// (`__init_tp` is `___init_tp`, `compiler_rt.memcpy` is `_compiler_rt.memcpy`); other formats do not.
fn source_name<'a>(image: &impl Image, symbol: &'a str) -> &'a str {
    match image.format() {
        Some(Format::MachO) => symbol.strip_prefix('_').unwrap_or(symbol),
        _ => symbol,
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
        for source in detection.sources {
            if !existing.sources.contains(&source) {
                existing.sources.push(source);
            }
        }
        existing.sources.sort();
        for version in detection.versions {
            if !existing.versions.contains(&version) {
                existing.versions.push(version);
            }
        }
        return;
    }
    detections.push(detection);
}

/// [`Binary`] viewed as an [`Image`]: sections by file offset (so unloaded sections such as `.comment` read),
/// imports from its import table, and the loader's overlay.
impl Image for Binary {
    fn format(&self) -> Option<Format> {
        Some(self.format)
    }

    fn entry_bytes(&self, len: usize) -> Option<&[u8]> {
        self.read(self.entry?, len as u64)
    }

    fn image_bytes(&self) -> &[u8] {
        Binary::image_bytes(self)
    }

    fn body_bytes(&self) -> &[u8] {
        let image = Binary::image_bytes(self);
        let end = self.overlay.and_then(|overlay| usize::try_from(overlay.offset).ok()).unwrap_or(image.len());
        &image[..end.min(image.len())]
    }

    fn overlay_bytes(&self) -> Option<&[u8]> {
        let image = Binary::image_bytes(self);
        image.get(usize::try_from(self.overlay?.offset).ok()?..)
    }

    fn codeview_guid(&self) -> Option<[u8; 16]> {
        match &self.details {
            Details::Pe(pe) => pe.codeview.as_ref().map(|record| record.guid),
            _ => None,
        }
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

    fn find_symbol(&self, test: &dyn Fn(&str) -> bool) -> Option<&str> {
        self.symbols.iter().map(|symbol| symbol.name.as_str()).find(|name| test(name))
    }

    fn build_tools(&self) -> Vec<(&str, &str)> {
        match &self.details {
            Details::MachO(macho) => {
                macho.build_tools.iter().map(|entry| (entry.tool.as_str(), entry.version.as_str())).collect()
            }
            _ => Vec::new(),
        }
    }

    fn overlay_size(&self) -> Option<u64> {
        self.overlay.map(|overlay| overlay.size)
    }

    fn entry(&self) -> Option<u64> {
        self.entry
    }

    fn read(&self, address: u64, len: usize) -> Option<&[u8]> {
        Binary::read(self, address, len as u64)
    }

    fn big_endian(&self) -> bool {
        self.big_endian
    }

    fn linked_libraries(&self) -> Vec<&str> {
        match &self.details {
            Details::Elf(elf) => elf.needed.iter().map(String::as_str).collect(),
            Details::MachO(macho) => {
                macho.dylibs.iter().map(|path| path.rsplit('/').next().unwrap_or(path.as_str())).collect()
            }
            _ => {
                let mut libraries: Vec<&str> = Vec::new();
                for library in self.imports.iter().filter_map(|import| import.library.as_deref()) {
                    if !libraries.contains(&library) {
                        libraries.push(library);
                    }
                }
                libraries
            }
        }
    }

    fn imported_functions(&self) -> Vec<(Option<&str>, &str)> {
        self.imports.iter().map(|import| (import.library.as_deref(), import.name.as_str())).collect()
    }

    fn exports(&self, name: &str) -> bool {
        self.exports.iter().any(|export| export.name == name)
    }

    fn pointer_bits(&self) -> Option<u8> {
        self.arch.pointer_size().map(|bytes| bytes * 8)
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
        format: Option<Format>,
        entry: Vec<u8>,
        image: Vec<u8>,
        sections: Vec<(String, Vec<u8>)>,
        libraries: Vec<String>,
        functions: Vec<String>,
        symbols: Vec<String>,
        tools: Vec<(String, String)>,
        overlay: Option<u64>,
        /// The overlay's contents; `overlay` alone gives only its size.
        appended: Vec<u8>,
        codeview: Option<[u8; 16]>,
        exported: Vec<String>,
        bits: Option<u8>,
    }

    impl Fake {
        fn with_section(mut self, name: &str, bytes: &[u8]) -> Self {
            self.sections.push((name.to_owned(), bytes.to_vec()));
            self
        }
    }

    impl Image for Fake {
        fn format(&self) -> Option<Format> {
            self.format
        }
        fn body_bytes(&self) -> &[u8] {
            &self.image
        }
        fn overlay_bytes(&self) -> Option<&[u8]> {
            (self.overlay.is_some() || !self.appended.is_empty()).then_some(self.appended.as_slice())
        }
        fn codeview_guid(&self) -> Option<[u8; 16]> {
            self.codeview
        }
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
        fn find_symbol(&self, test: &dyn Fn(&str) -> bool) -> Option<&str> {
            self.symbols.iter().map(String::as_str).find(|name| test(name))
        }
        fn build_tools(&self) -> Vec<(&str, &str)> {
            self.tools.iter().map(|(tool, version)| (tool.as_str(), version.as_str())).collect()
        }
        fn overlay_size(&self) -> Option<u64> {
            self.overlay
        }
        fn entry(&self) -> Option<u64> {
            (!self.entry.is_empty()).then_some(0)
        }
        fn read(&self, address: u64, len: usize) -> Option<&[u8]> {
            let start = usize::try_from(address).ok()?;
            self.entry.get(start..start.checked_add(len)?)
        }
        fn big_endian(&self) -> bool {
            false
        }
        fn linked_libraries(&self) -> Vec<&str> {
            self.libraries.iter().map(String::as_str).collect()
        }
        fn imported_functions(&self) -> Vec<(Option<&str>, &str)> {
            self.functions.iter().map(|name| (self.libraries.first().map(String::as_str), name.as_str())).collect()
        }
        fn exports(&self, name: &str) -> bool {
            self.exported.iter().any(|export| export == name)
        }
        fn pointer_bits(&self) -> Option<u8> {
            self.bits
        }
    }

    fn entry(pattern: &str) -> Condition {
        Condition::Entry { pattern: BytePattern::parse(pattern).unwrap(), ep_only: true }
    }

    /// Evaluates one signature on its own, as [`identify_image`] would.
    fn evaluate(image: &impl Image, signature: &Signature) -> Option<Detection> {
        let db = SignatureDb::from_signatures(vec![signature.clone()]);
        super::evaluate(image, &Unanchored::scan(image.body_bytes(), &db), &db.signatures[0])
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
    fn a_gcc_producer_in_pe_rdata_is_tentative_gcc_and_the_crt_banner_is_a_runtime() {
        let rdata = b"GCC: (GNU) 13.2.0\0Mingw-w64 runtime failure:\n\0";
        let image =
            Fake { format: Some(Format::Pe), image: rdata.to_vec(), ..Fake::default() }.with_section(".rdata", rdata);
        let detections = identify_image(&image, &SignatureDb::bundled());
        let found = |name: &str| detections.iter().find(|d| d.name == name).map(|d| (d.kind, d.confidence));
        assert_eq!(found("GCC"), Some((Kind::Compiler, Confidence::Tentative)));
        assert_eq!(found("MinGW-w64"), Some((Kind::Runtime, Confidence::Strong)));
        // The banner alone says nothing about the compiler.
        let banner = b"Mingw-w64 runtime failure:\n\0";
        let clang =
            Fake { format: Some(Format::Pe), image: banner.to_vec(), ..Fake::default() }.with_section(".rdata", banner);
        let detections = identify_image(&clang, &SignatureDb::bundled());
        assert!(detections.iter().all(|d| d.kind == Kind::Runtime), "{detections:?}");
        // An MSVC image has neither.
        let msvc = Fake { libraries: vec!["VCRUNTIME140.dll".to_owned()], ..Fake::default() };
        assert!(!identify_image(&msvc, &SignatureDb::bundled()).iter().any(|d| d.kind == Kind::Runtime));
    }

    #[test]
    fn the_mingw_banner_counts_only_in_a_pe_rdata() {
        let banner = b"Mingw-w64 runtime failure:\n\0";
        let mingw = |image: &Fake| identify_image(image, &SignatureDb::bundled()).iter().any(|d| d.name == "MinGW-w64");
        let pe = |section: &str| Fake { format: Some(Format::Pe), ..Fake::default() }.with_section(section, banner);
        assert!(mingw(&pe(".rdata")));
        assert!(!mingw(&pe(".data")), "writable data is not where the CRT keeps it");
        let macho = Fake { format: Some(Format::MachO), image: banner.to_vec(), ..Fake::default() };
        assert!(!mingw(&macho.with_section(".rdata", banner)), "a Mach-O carrying a PE's bytes");
        let appended = Fake { format: Some(Format::Pe), appended: banner.to_vec(), ..Fake::default() };
        assert!(!mingw(&appended));
    }

    #[test]
    fn the_musl_strerror_table_counts_only_in_an_elf_rodata() {
        let table = b"No error information\0Illegal byte sequence\0Domain error\0Result not representable\0";
        let musl = |image: &Fake| identify_image(image, &SignatureDb::bundled()).into_iter().find(|d| d.name == "musl");
        let elf = |section: &str| Fake { format: Some(Format::Elf), ..Fake::default() }.with_section(section, table);
        let found = musl(&elf(".rodata")).expect("musl from .rodata");
        assert_eq!(found.confidence, Confidence::Strong);
        assert!(musl(&elf(".data")).is_none());
        let macho = Fake { format: Some(Format::MachO), image: table.to_vec(), ..Fake::default() };
        assert!(musl(&macho.with_section(".rodata", table)).is_none());
    }

    #[test]
    fn lld_link_is_named_only_by_its_codeview_record() {
        let mut guid = [0x5a; 16];
        guid[8..].copy_from_slice(b"LLD PDB.");
        let lld = |image: &Fake| identify_image(image, &SignatureDb::bundled()).into_iter().find(|d| d.name == "LLD");
        let found = lld(&Fake { format: Some(Format::Pe), codeview: Some(guid), ..Fake::default() }).expect("LLD");
        assert_eq!(found.confidence, Confidence::Strong);
        assert!(found.evidence[0].starts_with("CodeView record GUID 5a5a"), "{:?}", found.evidence);
        assert!(lld(&Fake { codeview: Some([0x5a; 16]), ..Fake::default() }).is_none(), "link.exe's GUID");
        // The same record bytes in data, as an embedded PE carries them, are not this image's debug directory.
        let record = [b"RSDS".as_slice(), &guid, &[1, 0, 0, 0]].concat();
        assert!(lld(&Fake { format: Some(Format::Pe), image: record.clone(), ..Fake::default() }).is_none());
        assert!(lld(&Fake { format: Some(Format::MachO), image: record, ..Fake::default() }).is_none());
    }

    #[test]
    fn the_zig_libc_path_counts_only_in_debug_sections_of_the_format() {
        let path = b"/opt/homebrew/Cellar/zig/0.17.0/lib/zig/libc/glibc/start.S\0";
        let zig = |image: &Fake| identify_image(image, &SignatureDb::bundled()).into_iter().find(|d| d.name == "Zig");
        let image =
            |format, section: &str| Fake { format: Some(format), ..Fake::default() }.with_section(section, path);
        assert_eq!(zig(&image(Format::Elf, ".debug_line_str")).map(|d| d.confidence), Some(Confidence::Tentative));
        assert!(zig(&image(Format::MachO, "__debug_str")).is_some());
        assert!(zig(&image(Format::Elf, ".rodata")).is_none(), "a string in data is just a string");
        assert!(zig(&image(Format::MachO, ".debug_str")).is_none(), "Mach-O names DWARF __debug_*");
    }

    #[test]
    fn nsis_needs_its_pe_stub_and_its_appended_header() {
        let header = [0xdead_beef_u32.to_le_bytes().as_slice(), b"NullsoftInst"].concat();
        let nsis = |image: &Fake| identify_image(image, &SignatureDb::bundled()).into_iter().find(|d| d.name == "NSIS");
        let stub = |format| Fake { format: Some(format), ..Fake::default() }.with_section(".ndata", &[]);
        let installer = Fake { appended: header.clone(), ..stub(Format::Pe) };
        assert_eq!(nsis(&installer).map(|d| d.confidence), Some(Confidence::Strong));
        assert_eq!(nsis(&stub(Format::Pe)).map(|d| d.confidence), Some(Confidence::Tentative));
        // The magic in the image's own data, or appended to something with no NSIS stub, is no installer.
        assert!(nsis(&Fake { format: Some(Format::Pe), image: header.clone(), ..Fake::default() }).is_none());
        assert!(nsis(&Fake { format: Some(Format::Pe), appended: header.clone(), ..Fake::default() }).is_none());
        assert!(nsis(&Fake { appended: header, ..stub(Format::Elf) }).is_none());
    }

    #[test]
    fn inno_setup_needs_its_setup_data_appended_to_a_pe() {
        let data = b"Inno Setup Setup Data (6.2.2)\0".to_vec();
        let inno = |image: &Fake| identify_image(image, &SignatureDb::bundled()).iter().any(|d| d.name == "Inno Setup");
        assert!(inno(&Fake { format: Some(Format::Pe), appended: data.clone(), ..Fake::default() }));
        assert!(!inno(&Fake { format: Some(Format::Pe), image: data.clone(), ..Fake::default() }));
        assert!(!inno(&Fake { format: Some(Format::MachO), appended: data, ..Fake::default() }));
        let banner = b"Inno Setup".to_vec();
        assert!(!inno(&Fake { format: Some(Format::Pe), image: banner, ..Fake::default() }), "a bare banner");
    }

    #[test]
    fn unscoped_searches_are_strong_only_in_a_signature_that_names_its_format() {
        let needle = || Condition::SectionContains { section: None, needle: b"toolchain banner".to_vec() };
        let image = Fake { format: Some(Format::Pe), image: b"..toolchain banner..".to_vec(), ..Fake::default() };
        let loose = Signature::new("Tool", Kind::Compiler, vec![needle()]);
        assert_eq!(evaluate(&image, &loose).unwrap().confidence, Confidence::Tentative);
        let pinned = Signature::new("Tool", Kind::Compiler, vec![Condition::Format(Format::Pe), needle()]);
        let detection = evaluate(&image, &pinned).unwrap();
        assert_eq!(detection.confidence, Confidence::Strong);
        assert_eq!(detection.evidence, ["image contains \"toolchain banner\""]);
        let pattern = BytePattern::parse("74 6F 6F 6C 63 68 61 69").unwrap();
        let anywhere = Signature::new("Tool", Kind::Compiler, vec![Condition::Entry { pattern, ep_only: false }]);
        assert_eq!(evaluate(&image, &anywhere).unwrap().confidence, Confidence::Tentative);
        // A format is no signal: with one generic condition the match stays tentative.
        let section = Signature::new(
            "Tool",
            Kind::Packer,
            vec![Condition::Format(Format::Pe), Condition::SectionName("pec1".to_owned())],
        );
        let packed = Fake { format: Some(Format::Pe), ..Fake::default() }.with_section("pec1", &[]);
        assert_eq!(evaluate(&packed, &section).unwrap().confidence, Confidence::Tentative);
        assert!(evaluate(&Fake { format: Some(Format::Elf), ..packed }, &section).is_none());
    }

    #[test]
    fn musl_needs_both_tls_symbols_or_its_loader() {
        let db = SignatureDb::bundled();
        let musl = |image: &Fake| identify_image(image, &db).into_iter().find(|d| d.name == "musl");
        let symbols =
            |names: &[&str]| Fake { symbols: names.iter().map(|&n| n.to_owned()).collect(), ..Fake::default() };
        let both = musl(&symbols(&["main", "__init_tp", "__copy_tls"])).expect("musl from symbols");
        assert_eq!(both.evidence, ["symbol __init_tp present", "symbol __copy_tls present"]);
        assert_eq!(both.confidence, Confidence::Strong);
        assert!(musl(&symbols(&["__init_tp"])).is_none(), "one symbol could be anyone's");
        let dynamic = Fake::default().with_section(".interp", b"/lib/ld-musl-x86_64.so.1\0");
        assert_eq!(musl(&dynamic).map(|d| d.kind), Some(Kind::Runtime));
        let glibc = Fake::default().with_section(".interp", b"/lib64/ld-linux-x86-64.so.2\0");
        assert!(musl(&glibc).is_none());
    }

    #[test]
    fn mach_o_symbols_match_without_their_leading_underscore() {
        let db = SignatureDb::bundled();
        let found = |format, names: &[&str], tool: &str| {
            let image = Fake {
                format: Some(format),
                symbols: names.iter().map(|&n| n.to_owned()).collect(),
                ..Fake::default()
            };
            identify_image(&image, &db).into_iter().find(|d| d.name == tool)
        };
        let zig = found(Format::MachO, &["_main", "_compiler_rt.__negdf2"], "Zig").expect("Zig on Mach-O");
        assert_eq!(zig.evidence, ["symbol _compiler_rt.__negdf2 (prefix compiler_rt.)"]);
        let musl = found(Format::MachO, &["___init_tp", "___copy_tls"], "musl").expect("musl on Mach-O");
        assert_eq!(musl.evidence, ["symbol ___init_tp present", "symbol ___copy_tls present"]);
        // Only one underscore is the format's: Mach-O __init_tp is the C name _init_tp.
        assert!(found(Format::MachO, &["__init_tp", "__copy_tls"], "musl").is_none());
        // ELF and PE names are the source's own.
        assert!(found(Format::Elf, &["_compiler_rt.__negdf2"], "Zig").is_none());
        assert!(found(Format::Elf, &["compiler_rt.__negdf2"], "Zig").is_some());
    }

    #[test]
    fn a_symbol_prefix_needs_a_name_that_goes_on_past_it() {
        let sig = Signature::new("Zig", Kind::Compiler, vec![Condition::SymbolPrefix("compiler_rt.".to_owned())]);
        let symbols =
            |names: &[&str]| Fake { symbols: names.iter().map(|&n| n.to_owned()).collect(), ..Fake::default() };
        let hit = evaluate(&symbols(&["main", "compiler_rt.memcpy.memcpyFast"]), &sig).expect("prefix match");
        assert_eq!(hit.evidence, ["symbol compiler_rt.memcpy.memcpyFast (prefix compiler_rt.)"]);
        assert_eq!(hit.confidence, Confidence::Strong);
        assert!(evaluate(&symbols(&["compiler_rt.", "compiler_rt_init", "__udivti3"]), &sig).is_none());
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

    #[test]
    fn exact_name_and_offset_conditions_match_as_detect_it_easy_does() {
        let pe = Fake {
            format: Some(Format::Pe),
            image: b"MZ\x90\x00rest".to_vec(),
            libraries: vec!["KERNEL32.dll".to_owned()],
            functions: vec!["LoadLibraryA".to_owned()],
            exported: vec!["DllMain".to_owned()],
            appended: b"Inno".to_vec(),
            bits: Some(32),
            ..Fake::default()
        };
        let holds = |condition: Condition| evaluate(&pe, &Signature::new("T", Kind::Packer, vec![condition])).is_some();
        // A PE library name compares whole, ignoring case; elsewhere it is exact.
        assert!(holds(Condition::Library("kernel32.DLL".to_owned())));
        assert!(!holds(Condition::Library("kernel32".to_owned())));
        // Function names are case-sensitive, and a named library must be the one the function comes from.
        let import = |library: Option<&str>, name: &str| Condition::ImportedFunction {
            library: library.map(str::to_owned),
            name: name.to_owned(),
        };
        assert!(holds(import(None, "LoadLibraryA")));
        assert!(!holds(import(None, "loadlibrarya")));
        assert!(holds(import(Some("kernel32.dll"), "LoadLibraryA")));
        assert!(!holds(import(Some("user32.dll"), "LoadLibraryA")));
        assert!(holds(Condition::Export("DllMain".to_owned())));
        assert!(!holds(Condition::Export("dllmain".to_owned())));
        let pattern = |text: &str| BytePattern::parse(text).unwrap();
        assert!(holds(Condition::FileBytes { offset: 0, pattern: pattern("4D 5A") }));
        assert!(holds(Condition::FileBytes { offset: 2, pattern: pattern("90 00") }));
        assert!(!holds(Condition::FileBytes { offset: 1, pattern: pattern("4D 5A") }));
        // Overlay bytes are anchored at the overlay's start.
        assert!(holds(Condition::OverlayBytes(pattern("49 6E"))));
        assert!(!holds(Condition::OverlayBytes(pattern("6E 6F"))));
        assert!(holds(Condition::PointerBits(32)));
        assert!(!holds(Condition::PointerBits(64)));
        let elf = Fake { format: Some(Format::Elf), libraries: vec!["libc.so.6".to_owned()], ..Fake::default() };
        let library = |name: &str| Signature::new("T", Kind::Packer, vec![Condition::Library(name.to_owned())]);
        assert!(evaluate(&elf, &library("libc.so.6")).is_some());
        assert!(evaluate(&elf, &library("LIBC.so.6")).is_none());
    }

    #[test]
    fn bundled_detect_it_easy_signatures_match_synthetic_entry_points() {
        use crate::model::Source;
        use crate::pattern::JumpPiece;

        let db = SignatureDb::bundled();
        let (mut plain, mut jumps) = (0, 0);
        for signature in db.signatures.iter().filter(|signature| signature.source == Source::DetectItEasy) {
            let (format, entry) = match signature.conditions.as_slice() {
                [Condition::Format(format), Condition::Entry { pattern, .. }] => {
                    plain += 1;
                    (*format, pattern.example())
                }
                // Every jump displacement zero, so each jump lands just past itself.
                [Condition::Format(format), Condition::EntryJumps(pattern)] => {
                    jumps += 1;
                    let bytes = pattern.pieces().iter().flat_map(|piece| match piece {
                        JumpPiece::Bytes(bytes) => bytes.example(),
                        JumpPiece::Jump(size) => vec![0; usize::from(*size)],
                    });
                    (*format, bytes.collect())
                }
                _ => continue,
            };
            let image = Fake { format: Some(format), entry, ..Fake::default() };
            let found = evaluate(&image, signature).unwrap_or_else(|| panic!("{} misses its own bytes", signature.name));
            assert_eq!(found.sources, [Source::DetectItEasy]);
            assert_eq!(found.versions, signature.version.iter().cloned().collect::<Vec<_>>());
            assert!(found.evidence[0].starts_with("Detect It Easy "), "{:?}", found.evidence);
            // The same bytes in another container format are not the rule's business.
            let other = if format == Format::Pe { Format::Elf } else { Format::Pe };
            assert!(evaluate(&Fake { format: Some(other), ..image }, signature).is_none());
        }
        assert!(plain > 100 && jumps > 10, "{plain} plain, {jumps} jump patterns");
    }

    #[test]
    fn merged_detections_pool_sources_and_versions() {
        use crate::model::Source;

        let mut die = Signature::new("UPX", Kind::Packer, vec![Condition::SectionName("UPX1".to_owned())]);
        die.source = Source::DetectItEasy;
        die.version = Some("3.96".to_owned());
        die.origin = Some("Detect It Easy PE/x.sg".to_owned());
        let own = Signature::new("UPX", Kind::Packer, vec![Condition::SectionName("UPX0".to_owned())]);
        let db = SignatureDb::from_signatures(vec![own, die]);
        let image = Fake::default().with_section("UPX0", &[0; 4]).with_section("UPX1", &[0; 4]);
        let detections = identify_image(&image, &db);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].sources, [Source::Rampage, Source::DetectItEasy]);
        assert_eq!(detections[0].versions, ["3.96"]);
        assert_eq!(
            detections[0].evidence,
            ["section UPX0 present", "Detect It Easy PE/x.sg: section UPX1 present"]
        );
    }
}
