// All capa YAML below is hand-written for these tests, not copied from the capa-rules corpus, so no corpus
// attribution is required. The syntax mirrors Mandiant capa rules (github.com/mandiant/capa-rules, Apache-2.0).

use std::fs;

use super::{detect_capa, detect_capa_with_exports, load_capa_rules, load_capa_rules_from_str};
use crate::Capability;

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

fn detect(yaml: &str, imports: &[&str], strings: &[&str]) -> Vec<Capability> {
    let rules = load_capa_rules_from_str(yaml).expect("rules parse");
    detect_capa(&rules, &owned(imports), &owned(strings))
}

/// A file-scope rule named `name` whose `features:` list is `features`, written indented by any common amount.
fn file_rule(name: &str, features: &str) -> String {
    let lines: Vec<&str> = features.lines().filter(|line| !line.trim().is_empty()).collect();
    let indent = lines.iter().map(|line| line.len() - line.trim_start().len()).min().unwrap_or(0);
    let mut yaml = format!("rule:\n  meta:\n    name: {name}\n    scopes:\n      static: file\n  features:\n");
    for line in lines {
        yaml.push_str("    ");
        yaml.push_str(&line[indent..]);
        yaml.push('\n');
    }
    yaml
}

const AND_OR: &str = "
rule:
  meta:
    name: And Or Rule
    namespace: testing/combinators
    scopes:
      static: file
      dynamic: process
  features:
    - and:
      - or:
        - import: CreateFileW
        - api: kernel32.CreateFileA
      - substring: evil
";

#[test]
fn and_or_fires_on_positive_inputs() {
    let caps = detect(AND_OR, &["CreateFileW"], &["this is evil code"]);
    let cap = caps.iter().find(|c| c.id == "capa/testing/combinators/and-or-rule").expect("match");
    assert_eq!(cap.name, "And Or Rule");
    assert_eq!(cap.category, "testing");
    assert!(cap.evidence.contains(&"import:CreateFileW".to_string()));
    assert!(cap.evidence.contains(&"substring:evil".to_string()));
}

#[test]
fn and_or_matches_via_the_api_alternative() {
    // `api: kernel32.CreateFileA` is matched on the symbol portion against the import name.
    let caps = detect(AND_OR, &["CreateFileA"], &["evil"]);
    assert!(caps.iter().any(|c| c.id == "capa/testing/combinators/and-or-rule"));
}

#[test]
fn and_fails_when_a_required_branch_is_missing() {
    // The `or` branch matches but the required substring does not.
    let caps = detect(AND_OR, &["CreateFileW"], &["benign text"]);
    assert!(caps.is_empty());
}

const NOT_RULE: &str = "
rule:
  meta:
    name: Not Rule
    namespace: testing/negation
    scopes:
      static: file
      dynamic: process
  features:
    - and:
      - import: send
      - not:
        - import: WSAStartup
";

#[test]
fn not_matches_when_child_absent() {
    let caps = detect(NOT_RULE, &["send"], &[]);
    assert!(caps.iter().any(|c| c.id == "capa/testing/negation/not-rule"));
}

#[test]
fn not_blocks_when_child_present() {
    let caps = detect(NOT_RULE, &["send", "WSAStartup"], &[]);
    assert!(caps.is_empty());
}

const OPTIONAL_RULE: &str = "
rule:
  meta:
    name: Optional Rule
    namespace: testing/optional
    scopes:
      static: file
      dynamic: process
  features:
    - and:
      - import: connect
      - optional:
        - substring: beacon
";

#[test]
fn optional_does_not_block_when_absent() {
    let caps = detect(OPTIONAL_RULE, &["connect"], &[]);
    assert!(caps.iter().any(|c| c.id == "capa/testing/optional/optional-rule"));
}

#[test]
fn optional_contributes_evidence_when_present() {
    let caps = detect(OPTIONAL_RULE, &["connect"], &["beacon url"]);
    let cap = caps.iter().find(|c| c.id == "capa/testing/optional/optional-rule").expect("match");
    assert!(cap.evidence.contains(&"substring:beacon".to_string()));
}

const N_OR_MORE: &str = "
rule:
  meta:
    name: Injection Primitives
    namespace: testing/injection
    scopes:
      static: file
      dynamic: process
  features:
    - 2 or more:
      - import: VirtualAllocEx
      - import: WriteProcessMemory
      - import: CreateRemoteThread
";

#[test]
fn n_or_more_needs_its_threshold() {
    let one = detect(N_OR_MORE, &["VirtualAllocEx"], &[]);
    assert!(one.is_empty());
    let two = detect(N_OR_MORE, &["VirtualAllocEx", "WriteProcessMemory"], &[]);
    let cap = two.iter().find(|c| c.id == "capa/testing/injection/injection-primitives").expect("match");
    assert_eq!(cap.evidence.len(), 2);
}

const SECTION_STRING: &str = "
rule:
  meta:
    name: Section Or String
    namespace: testing/sections
    scopes:
      static: file
      dynamic: process
  features:
    - or:
      - section: .evilsec
      - string: exactmatch
";

#[test]
fn section_feature_matches_against_strings() {
    let caps = detect(SECTION_STRING, &[], &[".evilsec"]);
    let cap = caps.iter().find(|c| c.id == "capa/testing/sections/section-or-string").expect("match");
    assert!(cap.evidence.contains(&"section:.evilsec".to_string()));
}

#[test]
fn string_feature_is_exact_not_substring() {
    let exact = detect(SECTION_STRING, &[], &["exactmatch"]);
    assert!(exact.iter().any(|c| c.id == "capa/testing/sections/section-or-string"));
    // A superset string does not satisfy an exact `string` feature.
    let superset = detect(SECTION_STRING, &[], &["exactmatchXYZ"]);
    assert!(superset.is_empty());
}

const BYTES_AND: &str = "
rule:
  meta:
    name: Unevaluable And
    namespace: testing/unevaluable
    scopes:
      static: file
      dynamic: process
  features:
    - and:
      - import: malloc
      - bytes: 01 02 03 04
";

#[test]
fn unevaluable_leaf_makes_and_branch_fail() {
    let caps = detect(BYTES_AND, &["malloc"], &[]);
    assert!(caps.is_empty());
}

const BYTES_OR: &str = "
rule:
  meta:
    name: Unevaluable Or
    namespace: testing/unevaluable
    scopes:
      static: file
      dynamic: process
  features:
    - or:
      - bytes: 01 02 03 04
      - import: malloc
";

#[test]
fn unevaluable_leaf_is_ignored_in_or() {
    let caps = detect(BYTES_OR, &["malloc"], &[]);
    assert!(caps.iter().any(|c| c.id == "capa/testing/unevaluable/unevaluable-or"));
}

const MATCH_REF: &str = "
rule:
  meta:
    name: Match Ref
    namespace: testing/matchref
    scopes:
      static: file
      dynamic: process
  features:
    - and:
      - import: malloc
      - match: some/other/rule
";

#[test]
fn match_reference_is_unevaluable() {
    let caps = detect(MATCH_REF, &["malloc"], &[]);
    assert!(caps.is_empty());
}

const GLOBALS: &str = "
rule:
  meta:
    name: Globals Rule
    namespace: testing/globals
    scopes:
      static: file
      dynamic: process
  features:
    - and:
      - os: windows
      - arch: amd64
      - format: pe
      - import: malloc
";

#[test]
fn global_features_are_accepted() {
    let caps = detect(GLOBALS, &["malloc"], &[]);
    assert!(caps.iter().any(|c| c.id == "capa/testing/globals/globals-rule"));
}

const FUNCTION_SCOPED: &str = "
rule:
  meta:
    name: Function Scoped
    namespace: testing/func
    scopes:
      static: function
      dynamic: process
  features:
    - import: malloc
";

#[test]
fn function_scoped_rule_is_skipped() {
    let rules = load_capa_rules_from_str(FUNCTION_SCOPED).expect("parse");
    assert!(rules.is_empty());
    let caps = detect_capa(&rules, &owned(&["malloc"]), &[]);
    assert!(caps.is_empty());
}

const NO_SCOPE: &str = "
rule:
  meta:
    name: No Scope
    namespace: testing/default
  features:
    - import: malloc
";

#[test]
fn missing_scope_defaults_to_function_and_is_skipped() {
    // capa's default static scope is `function`, which this file-scope evaluator cannot assess.
    assert!(load_capa_rules_from_str(NO_SCOPE).expect("parse").is_empty());
    let legacy_file = "rule:\n  meta:\n    name: Legacy\n    scope: file\n  features:\n    - import: malloc\n";
    assert_eq!(detect(legacy_file, &["malloc"], &[]).len(), 1);
}

const MALLOC_FILE: &str = "
rule:
  meta:
    name: Malloc File
    scopes:
      static: file
  features:
    - import: malloc
";

#[test]
fn import_names_are_normalized() {
    // Leading underscore (Mach-O), an @plt suffix (ELF) and an __imp_ thunk prefix still compare equal.
    for name in ["_malloc@plt", "__imp_malloc", "MALLOC"] {
        let caps = detect(MALLOC_FILE, &[name], &[]);
        assert!(caps.iter().any(|c| c.id == "capa/malloc-file"), "{name}");
    }
}

const DESCRIBED: &str = "
rule:
  meta:
    name: Described
    namespace: testing/description
    scopes:
      static: file
  features:
    - and:
      - description: send a beacon
      - import: send
      - or:
        - comment: either marker
        - substring: beacon
";

#[test]
fn description_and_comment_items_are_annotations_not_conditions() {
    let caps = detect(DESCRIBED, &["send"], &["beacon url"]);
    let cap = caps.iter().find(|c| c.name == "Described").expect("match");
    assert_eq!(cap.evidence, ["import:send", "substring:beacon"]);
    assert!(detect(DESCRIBED, &["send"], &["benign"]).is_empty());

    let negated = file_rule(
        "Negated",
        "
        - and:
          - import: recv
          - not:
            - and:
              - description: x
              - import: send",
    );
    assert!(detect(&negated, &["recv", "send"], &[]).is_empty());
    assert_eq!(detect(&negated, &["recv"], &[]).len(), 1);
}

const CHARSET: &str = "
rule:
  meta:
    name: Charset
    scopes:
      static: file
  features:
    - or:
      - import: kernel32.CreateFile
      - api: user32.MessageBoxA
";

#[test]
fn charset_neutral_names_match_a_and_w_variants() {
    for import in ["CreateFileW", "CreateFileA", "CreateFile", "__imp_CreateFileW"] {
        assert_eq!(detect(CHARSET, &[import], &[]).len(), 1, "{import}");
    }
    // A rule that names one variant matches only that variant.
    assert_eq!(detect(CHARSET, &["MessageBoxA"], &[]).len(), 1);
    assert!(detect(CHARSET, &["MessageBoxW"], &[]).is_empty());
}

#[test]
fn evidence_free_and_negated_unevaluable_rules_do_not_fire() {
    let embedded = file_rule(
        "Embedded",
        "
        - and:
          - format: pe
          - not:
            - characteristic: embedded pe",
    );
    let rules = load_capa_rules_from_str(&embedded).expect("parse");
    assert!(rules.is_empty(), "no feature can supply evidence");
    assert!(detect_capa(&rules, &[], &[]).is_empty());

    let global_or = file_rule(
        "Global Or",
        "
        - or:
          - os: windows
          - import: malloc",
    );
    assert!(detect(&global_or, &[], &[]).is_empty());
    assert_eq!(detect(&global_or, &["malloc"], &[]).len(), 1);

    let not_bytes = file_rule(
        "Not Bytes",
        "
        - and:
          - import: send
          - not:
            - bytes: 01 02",
    );
    assert!(detect(&not_bytes, &["send"], &[]).is_empty());
}

#[test]
fn n_or_more_with_unknown_children_does_not_match() {
    let yaml = file_rule(
        "Two",
        "
        - 2 or more:
          - import: send
          - bytes: 01 02
          - mnemonic: xor",
    );
    assert!(detect(&yaml, &["send"], &[]).is_empty());
    // With `send` present the un-evaluable bytes decide the count, so the negation is unknown.
    let negated = file_rule(
        "Neg Two",
        "
        - and:
          - import: recv
          - not:
            - 2 or more:
              - import: send
              - bytes: 01 02",
    );
    assert!(detect(&negated, &["recv", "send"], &[]).is_empty());
    // Without `send` the count cannot reach two whatever the bytes are, so the negation is decided.
    assert_eq!(detect(&negated, &["recv"], &[]).len(), 1);
}

const EXPORTED: &str = "
rule:
  meta:
    name: Exported
    scopes:
      static: file
  features:
    - export: ServiceMain
";

#[test]
fn export_features_need_an_export_list() {
    // An import of the same name is not an export.
    assert!(detect(EXPORTED, &["ServiceMain"], &[]).is_empty());
    let rules = load_capa_rules_from_str(EXPORTED).expect("parse");
    let caps = detect_capa_with_exports(&rules, &[], &owned(&["ServiceMain"]), &[]);
    assert_eq!(caps[0].evidence, ["export:ServiceMain"]);
    assert!(detect_capa_with_exports(&rules, &owned(&["ServiceMain"]), &[], &[]).is_empty());
}

#[test]
fn ordinal_imports_are_unevaluable() {
    let yaml = file_rule(
        "Ordinal",
        "
        - and:
          - import: recv
          - not:
            - import: ws2_32.#23",
    );
    // Neither `#23` from another DLL nor its absence says anything about ws2_32 ordinal 23.
    assert!(detect(&yaml, &["recv"], &[]).is_empty());
    assert!(detect(&yaml, &["recv", "#23"], &[]).is_empty());
    let positive = file_rule(
        "Ordinal Or",
        "
        - or:
          - import: ws2_32.#23
          - import: socket",
    );
    assert!(detect(&positive, &["#23"], &[]).is_empty());
}

#[test]
fn repeated_evidence_is_reported_once() {
    let yaml = file_rule(
        "Repeat",
        "
        - and:
          - import: send
          - substring: beacon
          - import: send",
    );
    let caps = detect(&yaml, &["send"], &["beacon"]);
    assert_eq!(caps[0].evidence, ["import:send", "substring:beacon"]);
}

#[test]
fn rule_ids_are_namespaced_and_unique() {
    let yaml = "
rule:
  meta:
    name: registry
    scopes:
      static: file
  features:
    - import: RegOpenKeyExW
---
rule:
  meta:
    name: Registry
    namespace: host-interaction/registry
    scopes:
      static: file
  features:
    - import: RegOpenKeyExW
---
rule:
  meta:
    name: registry!
    namespace: host-interaction/registry
    scopes:
      static: file
  features:
    - import: RegOpenKeyExW
";
    let ids: Vec<String> = detect(yaml, &["RegOpenKeyExW"], &[]).into_iter().map(|c| c.id.into_owned()).collect();
    assert_eq!(
        ids,
        ["capa/registry", "capa/host-interaction/registry/registry", "capa/host-interaction/registry/registry-2"]
    );
}

#[test]
fn regex_strings_with_flags_are_not_literals() {
    let yaml = file_rule(
        "Regex",
        "
        - or:
          - string: /evil/i
          - string: /usr/bin",
    );
    // `/evil/i` is a regex (un-evaluable); `/usr/bin` is not regex-shaped and stays a literal.
    assert!(detect(&yaml, &[], &["/evil/i"]).is_empty());
    assert_eq!(detect(&yaml, &[], &["/usr/bin"]).len(), 1);
}

#[test]
fn malformed_yaml_returns_error_not_panic() {
    let result = load_capa_rules_from_str("rule: [unterminated");
    assert!(result.is_err());
}

#[test]
fn non_rule_yaml_is_skipped_without_error() {
    let rules = load_capa_rules_from_str("not_a_rule: true").expect("parse");
    assert!(rules.is_empty());
}

#[test]
fn directory_loader_reads_rule_files() {
    let dir = std::env::temp_dir().join(format!("rampage-capa-{}", std::process::id()));
    let nested = dir.join("sub");
    fs::create_dir_all(&nested).expect("mkdir");
    fs::write(dir.join("a.yml"), AND_OR).expect("write a");
    fs::write(nested.join("b.yaml"), NOT_RULE).expect("write b");
    fs::write(dir.join("notyaml.txt"), "ignored").expect("write txt");

    let rules = load_capa_rules(&dir).expect("load dir");
    assert_eq!(rules.len(), 2);
    let caps = detect_capa(&rules, &owned(&["send"]), &["evil"].iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert!(caps.iter().any(|c| c.id == "capa/testing/negation/not-rule"));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn parsed_metadata_is_exposed() {
    let yaml = "
rule:
  meta:
    name: Meta Rule
    namespace: collection/keylog
    authors:
      - analyst@example.com
    att&ck:
      - Collection::Input Capture [T1056]
    mbc:
      - Collection::Keylogging [E1056]
    scopes:
      static: file
      dynamic: process
  features:
    - import: GetAsyncKeyState
";
    let rules = load_capa_rules_from_str(yaml).expect("parse");
    let rule = &rules.rules()[0];
    assert_eq!(rule.name, "Meta Rule");
    assert_eq!(rule.namespace, "collection/keylog");
    assert_eq!(rule.authors, vec!["analyst@example.com".to_string()]);
    assert_eq!(rule.attack, vec!["Collection::Input Capture [T1056]".to_string()]);
    assert_eq!(rule.mbc, vec!["Collection::Keylogging [E1056]".to_string()]);
}
