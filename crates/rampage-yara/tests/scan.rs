use std::path::PathBuf;

use rampage_loaders::Binary;
use rampage_yara::{MAX_MATCHED_STRINGS_PER_RULE, MatchedString, compile, scan, scan_binary};

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
    assert_eq!(hits[0].matched_strings, vec![MatchedString { identifier: "$s".to_string(), offset: 8, length: 6 }]);

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
fn a_slow_rule_stops_at_the_timeout() {
    let slow = "rule slow { condition: for all i in (0..100000000000) : (uint8(i % filesize) < 0x100) }";
    let rules = compile(slow).unwrap().with_timeout(std::time::Duration::ZERO);
    let started = std::time::Instant::now();
    let result = scan(&rules, b"some bytes");
    assert!(matches!(result, Err(rampage_yara::YaraError::Timeout(_))), "{result:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn unreadable_rule_file_error_names_the_cause() {
    let missing = std::env::temp_dir().join(format!("rampage-yara-missing-{}.yar", std::process::id()));
    let message = rampage_yara::compile_files(&[&missing]).err().expect("missing file fails").to_string();
    let cause = std::fs::read(&missing).unwrap_err().to_string();
    assert!(message.ends_with(&format!(": {cause}")), "{message}");
}

#[test]
fn a_directory_without_rule_files_is_an_error() {
    let dir = std::env::temp_dir().join(format!("rampage-yara-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("notes.txt"), "not a rule").unwrap();
    let result = rampage_yara::compile_dir(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(matches!(result, Err(rampage_yara::YaraError::NoRuleFiles(_))));
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
    assert_eq!(hits[0].total_matched_strings, data.len());
}

#[test]
fn a_prolific_pattern_does_not_crowd_out_the_others() {
    let rules = compile("rule two { strings: $a = \"A\" $b = \"needle\" condition: $a and $b }").unwrap();
    let mut data = vec![b'A'; MAX_MATCHED_STRINGS_PER_RULE * 4];
    data.extend_from_slice(b"needle");
    let hits = scan(&rules, &data).unwrap();
    let strings = &hits[0].matched_strings;
    assert_eq!(strings.len(), MAX_MATCHED_STRINGS_PER_RULE);
    assert_eq!(
        strings.last(),
        Some(&MatchedString { identifier: "$b".to_string(), offset: data.len() - 6, length: 6 })
    );
    assert_eq!(hits[0].total_matched_strings, MAX_MATCHED_STRINGS_PER_RULE * 4 + 1);
}
