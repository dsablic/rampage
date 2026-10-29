use super::*;
use crate::pe_test_image::{SECTION_RVA, TestPe};

const DIRECTORY: usize = object::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE;
const IS_TABLE: u32 = 0x8000_0000;
const IS_NAME: u32 = 0x8000_0000;

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn pad4(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}

/// A VS_VERSIONINFO-style node. Text values are NUL-terminated UTF-16 with their length counted in characters.
fn node(key: &str, value: Option<&str>, binary: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; 6];
    bytes.extend(utf16(key));
    bytes.extend([0, 0]);
    pad4(&mut bytes);
    let (value_length, value_type) = match value {
        Some(text) => {
            bytes.extend(utf16(text));
            bytes.extend([0, 0]);
            (text.encode_utf16().count() + 1, 1u16)
        }
        None => {
            bytes.extend(binary);
            (binary.len(), 0)
        }
    };
    for child in children {
        pad4(&mut bytes);
        bytes.extend(child);
    }
    let length = bytes.len() as u16;
    bytes[0..2].copy_from_slice(&length.to_le_bytes());
    bytes[2..4].copy_from_slice(&(value_length as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&value_type.to_le_bytes());
    bytes
}

fn fixed_file_info() -> Vec<u8> {
    let words: [u32; 13] =
        [0xfeef_04bd, 0x0001_0000, 0x0001_0002, 0x0003_0004, 0x0005_0006, 0x0007_0008, 0x3f, 0x2, 0x40004, 1, 0, 0, 0];
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn version_blob() -> Vec<u8> {
    let strings = node(
        "040904B0",
        None,
        &[],
        &[node("CompanyName", Some("Rampage Fixtures"), &[], &[]), node("ProductName", Some("rampage"), &[], &[])],
    );
    let translation = node("Translation", None, &[0x09, 0x04, 0xb0, 0x04], &[]);
    node(
        "VS_VERSION_INFO",
        None,
        &fixed_file_info(),
        &[node("StringFileInfo", None, &[], &[strings]), node("VarFileInfo", None, &[], &[translation])],
    )
}

const MANIFEST: &str = "\u{feff}<?xml version=\"1.0\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">\
    <asmv3:trustInfo><asmv3:requestedExecutionLevel level='asInvoker' uiAccess=\"false\"/></asmv3:trustInfo>\
    <dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\"/>\
    </dependentAssembly></dependency></assembly>";

/// A resource section under construction: tables, entries and data entries at chosen offsets.
struct Tree {
    bytes: Vec<u8>,
}

impl Tree {
    fn new(size: usize) -> Self {
        Self { bytes: vec![0; size] }
    }

    fn put(&mut self, at: usize, value: u32) {
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// A table at `at` with the given (name_or_id, offset_to_data_or_directory) entries: named ones first.
    fn table(&mut self, at: usize, named: u16, entries: &[(u32, u32)]) {
        self.bytes[at + 12..at + 14].copy_from_slice(&named.to_le_bytes());
        self.bytes[at + 14..at + 16].copy_from_slice(&(entries.len() as u16 - named).to_le_bytes());
        for (index, &(name, offset)) in entries.iter().enumerate() {
            self.put(at + 16 + index * 8, name);
            self.put(at + 20 + index * 8, offset);
        }
    }

    fn data(&mut self, at: usize, rva: u32, size: u32) {
        self.put(at, rva);
        self.put(at + 4, size);
        self.put(at + 8, 1252);
    }

    fn name(&mut self, at: usize, text: &str) {
        let units = utf16(text);
        self.bytes[at..at + 2].copy_from_slice(&((units.len() / 2) as u16).to_le_bytes());
        self.bytes[at + 2..at + 2 + units.len()].copy_from_slice(&units);
    }

    fn payload(&mut self, at: usize, bytes: &[u8]) -> (u32, u32) {
        self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
        (SECTION_RVA + at as u32, bytes.len() as u32)
    }

    fn image(self, bits: u8) -> Vec<u8> {
        let size = self.bytes.len() as u32;
        TestPe::new(bits, self.bytes).directory(DIRECTORY, SECTION_RVA, size).build()
    }
}

/// RT_VERSION 1/0x409, RT_MANIFEST 1/0x409 and a string-named type FIXTURE/7/0.
fn regular_tree() -> Tree {
    let mut tree = Tree::new(0x1000);
    tree.table(0, 1, &[(IS_NAME | 0x300, IS_TABLE | 0x40), (16, IS_TABLE | 0x80), (24, IS_TABLE | 0xc0)]);
    tree.name(0x300, "FIXTURE");
    tree.table(0x40, 0, &[(7, IS_TABLE | 0x100)]);
    tree.table(0x80, 0, &[(1, IS_TABLE | 0x140)]);
    tree.table(0xc0, 0, &[(1, IS_TABLE | 0x180)]);
    tree.table(0x100, 0, &[(0, 0x200)]);
    tree.table(0x140, 0, &[(0x409, 0x210)]);
    tree.table(0x180, 0, &[(0x409, 0x220)]);
    let (rva, size) = tree.payload(0x400, b"custom");
    tree.data(0x200, rva, size);
    let (rva, size) = tree.payload(0x500, &version_blob());
    tree.data(0x210, rva, size);
    let (rva, size) = tree.payload(0x900, MANIFEST.as_bytes());
    tree.data(0x220, rva, size);
    tree
}

#[test]
fn lists_every_leaf_with_its_type_name_and_language() {
    for bits in [32, 64] {
        let image = regular_tree().image(bits);
        let report = parse_resources(&image).unwrap().unwrap();
        assert_eq!(report.warnings, Vec::<String>::new());
        assert_eq!(report.directory_rva, Some(SECTION_RVA));
        assert!(!report.truncated);
        assert_eq!((report.tables_visited, report.entries_visited), (7, 9));
        let summary: Vec<_> = report
            .leaves
            .iter()
            .map(|leaf| (leaf.type_name.as_str(), leaf.name.clone(), leaf.language.clone(), leaf.in_file))
            .collect();
        assert_eq!(
            summary,
            [
                ("FIXTURE", Some(ResourceKey::Id(7)), Some(ResourceKey::Id(0)), true),
                ("RT_VERSION", Some(ResourceKey::Id(1)), Some(ResourceKey::Id(0x409)), true),
                ("RT_MANIFEST", Some(ResourceKey::Id(1)), Some(ResourceKey::Id(0x409)), true),
            ]
        );
        let custom = &report.leaves[0];
        assert_eq!(custom.type_key, ResourceKey::Name("FIXTURE".to_owned()));
        assert_eq!(custom.bytes(&image), Some(&b"custom"[..]));
        assert_eq!(custom.code_page, 1252);
        assert_eq!(decode(&image, custom), None);
        assert!(report.leaves[1].matches_type("rt_version") && report.leaves[1].matches_type("VERSION"));
        assert!(report.leaves[1].matches_type("16") && !report.leaves[1].matches_type("RT_ICON"));
        assert!(custom.matches_type("fixture") && !custom.matches_type("7"));
    }
}

#[test]
fn decodes_version_information() {
    let image = regular_tree().image(64);
    let report = parse_resources(&image).unwrap().unwrap();
    let Some(ResourcePayload::Version(version)) = decode(&image, &report.leaves[1]) else { panic!("not a version") };
    assert_eq!(version.warnings, Vec::<String>::new());
    assert!(!version.truncated);
    let fixed = version.fixed.unwrap();
    assert_eq!((fixed.file_version.as_str(), fixed.product_version.as_str()), ("1.2.3.4", "5.6.7.8"));
    assert_eq!(
        (fixed.flag_names, fixed.os_name, fixed.file_type_name),
        (vec!["prerelease"], Some("nt_windows32"), Some("app"))
    );
    assert_eq!(version.string_tables.len(), 1);
    let table = &version.string_tables[0];
    assert_eq!((table.key.as_str(), table.language, table.code_page), ("040904B0", Some(0x409), Some(1200)));
    let pairs: Vec<_> = table.strings.iter().map(|string| (string.key.as_str(), string.value.as_str())).collect();
    assert_eq!(pairs, [("CompanyName", "Rampage Fixtures"), ("ProductName", "rampage")]);
    assert_eq!(version.translations, [Translation { language: 0x409, code_page: 1200 }]);
}

#[test]
fn decodes_manifest_text_level_and_dependencies() {
    let image = regular_tree().image(32);
    let report = parse_resources(&image).unwrap().unwrap();
    let Some(ResourcePayload::Manifest(manifest)) = decode(&image, &report.leaves[2]) else { panic!("no manifest") };
    assert!(manifest.text.starts_with("<?xml") && !manifest.text_truncated && !manifest.scan_truncated);
    let level = manifest.requested_execution_level.unwrap();
    assert_eq!((level.level.as_deref(), level.ui_access.as_deref()), (Some("asInvoker"), Some("false")));
    assert_eq!(manifest.dependent_assemblies, ["Microsoft.Windows.Common-Controls"]);
}

#[test]
fn a_loop_back_to_the_root_is_visited_once() {
    let mut tree = Tree::new(0x400);
    tree.table(0, 0, &[(3, IS_TABLE | 0x40)]);
    tree.table(0x40, 0, &[(1, IS_TABLE), (2, IS_TABLE | 0x40)]);
    let report = parse_resources(&tree.image(64)).unwrap().unwrap();
    assert!(report.leaves.is_empty());
    assert_eq!(report.tables_visited, 2);
    assert_eq!(report.warnings.iter().filter(|warning| warning.contains("referenced again")).count(), 2);
}

#[test]
fn tables_below_the_language_level_are_not_followed() {
    let mut tree = Tree::new(0x400);
    tree.table(0, 0, &[(3, IS_TABLE | 0x40)]);
    tree.table(0x40, 0, &[(1, IS_TABLE | 0x80)]);
    tree.table(0x80, 0, &[(0x409, IS_TABLE | 0xc0)]);
    tree.table(0xc0, 0, &[(0, 0x100)]);
    tree.data(0x100, SECTION_RVA, 4);
    let report = parse_resources(&tree.image(64)).unwrap().unwrap();
    assert!(report.leaves.is_empty());
    assert!(report.warnings.iter().any(|warning| warning.contains("nests deeper")), "{:?}", report.warnings);
}

#[test]
fn shallow_leaves_are_kept_with_missing_levels() {
    let mut tree = Tree::new(0x400);
    tree.table(0, 0, &[(10, IS_TABLE | 0x40)]);
    tree.table(0x40, 0, &[(5, 0x80)]);
    tree.data(0x80, SECTION_RVA + 0x100, 8);
    let report = parse_resources(&tree.image(64)).unwrap().unwrap();
    assert_eq!(report.leaves.len(), 1);
    assert_eq!((report.leaves[0].type_name.as_str(), report.leaves[0].language.clone()), ("RT_RCDATA", None));
    assert!(report.warnings.iter().any(|warning| warning.contains("above the language level")));
}

#[test]
fn data_outside_the_file_is_located_but_not_read() {
    let mut tree = Tree::new(0x400);
    tree.table(0, 0, &[(16, IS_TABLE | 0x40)]);
    tree.table(0x40, 0, &[(1, IS_TABLE | 0x80)]);
    tree.table(0x80, 0, &[(0x409, 0xc0), (0x407, 0xd0)]);
    // Starts in the section but runs past it; starts beyond every section.
    tree.data(0xc0, SECTION_RVA + 0x3f0, 0x100);
    tree.data(0xd0, 0x9000, 0x10);
    let image = tree.image(64);
    let report = parse_resources(&image).unwrap().unwrap();
    let leaves = &report.leaves;
    assert_eq!(leaves.len(), 2);
    assert!(!leaves[0].in_file && leaves[0].file_offset.is_some());
    assert!(!leaves[1].in_file && leaves[1].file_offset.is_none());
    assert!(leaves.iter().all(|leaf| leaf.bytes(&image).is_none() && decode(&image, leaf).is_none()));
    assert_eq!(report.warnings.iter().filter(|warning| warning.contains("not all in the file")).count(), 2);
}

#[test]
fn oversized_entry_counts_are_reported_not_read() {
    let mut tree = Tree::new(0x100);
    tree.bytes[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    let report = parse_resources(&tree.image(64)).unwrap().unwrap();
    assert!(report.leaves.is_empty());
    assert!(report.warnings[0].contains("root table is unreadable"), "{:?}", report.warnings);

    let mut tree = Tree::new(0x100);
    tree.table(0, 0, &[(3, IS_TABLE | 0x40)]);
    tree.bytes[0x40 + 12..0x40 + 16].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    let report = parse_resources(&tree.image(64)).unwrap().unwrap();
    assert!(report.warnings[0].contains("offset 0x40 is unreadable"), "{:?}", report.warnings);
}

#[test]
fn a_truncated_directory_is_a_warning() {
    let tree = regular_tree();
    let image = TestPe::new(64, tree.bytes).directory(DIRECTORY, SECTION_RVA, 0x2000).build();
    let report = parse_resources(&image).unwrap().unwrap();
    assert!(report.leaves.is_empty());
    assert!(report.warnings[0].contains("directory at RVA 0x1000 is unreadable"), "{:?}", report.warnings);
}

#[test]
fn the_leaf_limit_truncates_the_walk() {
    let count = MAX_RESOURCE_LEAVES + 1;
    let mut tree = Tree::new(0x100 + count * 8 + 0x100);
    tree.table(0, 0, &[(3, IS_TABLE | 0x40)]);
    tree.table(0x40, 0, &[(1, IS_TABLE | 0x80)]);
    let entries: Vec<(u32, u32)> = (0..count as u32).map(|language| (language, 0x60)).collect();
    tree.data(0x60, SECTION_RVA, 4);
    tree.table(0x80, 0, &entries);
    let report = parse_resources(&tree.image(64)).unwrap().unwrap();
    assert!(report.truncated);
    assert_eq!(report.leaves.len(), MAX_RESOURCE_LEAVES);
}

#[test]
fn long_names_are_capped() {
    let mut tree = Tree::new(0x800);
    tree.table(0, 1, &[(IS_NAME | 0x100, IS_TABLE | 0x40)]);
    tree.name(0x100, &"N".repeat(MAX_RESOURCE_NAME_UNITS + 10));
    tree.table(0x40, 0, &[(1, IS_TABLE | 0x80)]);
    tree.table(0x80, 0, &[(0, 0xc0)]);
    tree.data(0xc0, SECTION_RVA, 4);
    let report = parse_resources(&tree.image(64)).unwrap().unwrap();
    let ResourceKey::Name(name) = &report.leaves[0].type_key else { panic!("not named") };
    assert_eq!(name.chars().count(), MAX_RESOURCE_NAME_UNITS + 1);
    assert!(name.ends_with('…'));
}

#[test]
fn non_pe_images_have_no_resources() {
    assert!(matches!(parse_resources(b"\x7fELF not really"), Ok(None)));
    let image = TestPe::new(64, vec![0; 16]).build();
    let report = parse_resources(&image).unwrap().unwrap();
    assert_eq!((report.directory_rva, report.leaves.len()), (None, 0));
}

#[test]
fn hostile_version_nodes_stay_bounded() {
    // A child that claims more bytes than its parent holds is clamped, with a warning.
    let mut blob = version_blob();
    let strings_at =
        blob.windows(utf16("StringFileInfo").len()).position(|w| w == utf16("StringFileInfo")).unwrap() - 6;
    blob[strings_at..strings_at + 2].copy_from_slice(&0xfff0u16.to_le_bytes());
    let version = version::parse(&blob);
    assert!(version.fixed.is_some());
    assert!(version.warnings.iter().any(|warning| warning.contains("remain")), "{:?}", version.warnings);

    // A zero-length node ends its sibling list instead of looping.
    let mut blob = version_blob();
    blob[strings_at..strings_at + 2].copy_from_slice(&0u16.to_le_bytes());
    let version = version::parse(&blob);
    assert!(version.string_tables.is_empty());
    assert!(version.warnings.iter().any(|warning| warning.contains("fewer than its header")));

    // Thousands of empty siblings stop at the node budget.
    let child = node("k", Some(""), &[], &[]);
    let table = node("040904B0", None, &[], &vec![child; 2000]);
    let blob = node("VS_VERSION_INFO", None, &fixed_file_info(), &[node("StringFileInfo", None, &[], &[table])]);
    let blob = &blob[..blob.len().min(MAX_VERSION_BYTES)];
    let version = version::parse(blob);
    assert!(version.truncated);
    assert!(version.string_tables[0].strings.len() <= MAX_VERSION_STRINGS);

    // Short or signature-less fixed info is reported, not guessed.
    let version = version::parse(&node("VS_VERSION_INFO", None, &[1, 2, 3, 4], &[]));
    assert!(version.fixed.is_none() && !version.warnings.is_empty());
    assert!(version::parse(&[0xff; 3]).warnings[0].contains("no readable root"));
}

#[test]
fn manifest_scanning_is_bounded() {
    let long = format!("<assembly>{}</assembly>", "x".repeat(MAX_MANIFEST_TEXT + 100));
    let manifest = manifest::parse(long.as_bytes());
    assert!(manifest.text_truncated && manifest.text.len() == MAX_MANIFEST_TEXT);
    assert!(manifest.requested_execution_level.is_none() && manifest.dependent_assemblies.is_empty());

    let many: String = (0..MAX_MANIFEST_DEPENDENCIES + 5)
        .map(|index| format!("<dependentAssembly><assemblyIdentity name=\"a{index}\"/></dependentAssembly>"))
        .collect();
    let manifest = manifest::parse(many.as_bytes());
    assert_eq!(manifest.dependent_assemblies.len(), MAX_MANIFEST_DEPENDENCIES);
    assert!(manifest.scan_truncated);

    // A lookalike name, a closing tag and an unquoted attribute are not taken as the element.
    let tricky = "<requestedExecutionLevelX level=\"no\"/></requestedExecutionLevel>\
                  <requestedExecutionLevel xlevel=\"no\" level=yes/>";
    let level = manifest::parse(tricky.as_bytes()).requested_execution_level.unwrap();
    assert_eq!(level.level, None);
    // Multi-byte text is cut on a character boundary.
    let wide = format!("a{}", "é".repeat(MAX_MANIFEST_TEXT));
    let manifest = manifest::parse(wide.as_bytes());
    assert!(manifest.text.len() <= MAX_MANIFEST_TEXT && !manifest.text.contains('\u{fffd}'));
}
