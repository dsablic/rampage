use std::path::PathBuf;

use rampage_loaders::Binary;
use rampage_yara::{compile, scan, scan_binary, MatchedString, MAX_MATCHED_STRINGS_PER_RULE};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn mz_at_zero_matches_and_non_matching_bytes_do_not() {
    let rules = compile("rule has_mz { strings: $m = \"MZ\" condition: $m at 0 }").unwrap();

    let hits = scan(&rules, b"MZ\x90\x00rest of header").unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].identifier, "has_mz");

    let misses = scan(&rules, b"not a dos header").unwrap();
    assert!(misses.is_empty());
}

#[test]
fn string_anywhere_matches_and_reports_offset() {
    let rules = compile("rule needle { strings: $s = \"needle\" condition: $s }").unwrap();

    let hits = scan(&rules, b"hay hay needle hay").unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].matched_strings, vec![MatchedString {
        identifier: "$s".to_string(),
        offset: 8,
        length: 6,
    }]);

    assert!(scan(&rules, b"only hay here").unwrap().is_empty());
}

#[test]
fn metadata_and_tags_round_trip() {
    let source = "rule tagged : alpha beta {\n\
        meta:\n\
            author = \"denis\"\n\
            severity = 7\n\
            enabled = true\n\
        strings:\n\
            $a = \"abc\"\n\
        condition:\n\
            $a\n\
    }";
    let rules = compile(source).unwrap();
    let hits = scan(&rules, b"xxabcxx").unwrap();
    assert_eq!(hits.len(), 1);

    let m = &hits[0];
    assert_eq!(m.tags, vec!["alpha".to_string(), "beta".to_string()]);
    assert_eq!(m.metadata.get("author").map(String::as_str), Some("denis"));
    assert_eq!(m.metadata.get("severity").map(String::as_str), Some("7"));
    assert_eq!(m.metadata.get("enabled").map(String::as_str), Some("true"));
}

#[test]
fn malformed_rule_returns_compile_error_not_panic() {
    let result = compile("rule broken { condition: }");
    assert!(matches!(result, Err(rampage_yara::YaraError::Compile(_))));
}

#[test]
fn scan_binary_matches_mz_header_of_pe_fixture() {
    let binary = Binary::open(fixture("hello-x64.exe")).unwrap();
    let rules = compile("rule dos_header { strings: $mz = \"MZ\" condition: $mz at 0 }").unwrap();

    let hits = scan_binary(&rules, &binary).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].identifier, "dos_header");
}

#[test]
fn matched_string_capture_is_bounded() {
    // A single-byte pattern over a long input matches far more than the cap allows.
    let rules = compile("rule many { strings: $a = \"A\" condition: #a > 10 }").unwrap();
    let data = vec![b'A'; MAX_MATCHED_STRINGS_PER_RULE * 4];

    let hits = scan(&rules, &data).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].matched_strings.len(), MAX_MATCHED_STRINGS_PER_RULE);
}
