//! Imports Mandiant capa rules (github.com/mandiant/capa-rules, Apache-2.0) as a capability source.
//!
//! capa rules are a large curated behavior corpus. This module parses their YAML and evaluates the SUBSET of
//! features rampage can assess from imports and strings alone, emitting the crate's `Capability` shape. It is a
//! deliberately partial evaluator -- NOT a reimplementation of capa -- so matches remain triage-grade evidence.
//!
//! Supported statements: `and`, `or`, `not`, `optional`, and `N or more`. Supported leaf features:
//! `import`/`api`/`export` (matched against import names), `string` (exact), `substring` (contains), `section`
//! (matched against the provided strings, since rampage is not given a section list here), and the globals
//! `os`/`arch`/`format` (accepted as always-satisfiable because no target context is supplied).
//!
//! Skipped on purpose, each treated as an un-evaluable leaf that does NOT match (so an `and` containing one
//! fails, an `or` ignores it):
//!   - Non-file features we cannot assess from imports/strings: `bytes`, `number`, `offset`, `mnemonic`,
//!     `characteristic`, `operand`, `property`, and any `count(...)` feature.
//!   - `match:` references to other rules (we have no rule-match graph, so the reference never matches).
//!   - `string:` written as a `/regex/` (we only do literal exact/substring matching).
//!   - Sub-scope statements `function` / `basic block` / `instruction` / `call` / `process` / `thread` /
//!     `span of calls` and their subtrees.
//!
//! Whole rules are skipped when their static scope is not `file` (function/basic-block/instruction/dynamic
//! rules), and when the rule has no evaluable feature tree. A `not` wrapped around an un-evaluable leaf is
//! therefore true (absence of something we cannot see); this is an accepted imprecision of a partial evaluator.

use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_yaml_ng::Value;

use super::{Capability, names};

/// Hard caps keep loading and evaluation bounded and panic-free on adversarial input.
const MAX_RULES: usize = 100_000;
const MAX_DEPTH: usize = 64;

/// Errors from loading capa rules. Malformed YAML surfaces here rather than panicking.
#[derive(Debug)]
pub enum CapaError {
    /// A rule directory or file could not be read.
    Io { path: PathBuf, source: std::io::Error },
    /// A YAML document failed to parse.
    Parse { path: Option<PathBuf>, source: serde_yaml_ng::Error },
    /// More than `MAX_RULES` rules were encountered; loading was stopped.
    LimitExceeded,
}

impl std::fmt::Display for CapaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::Parse { path: Some(path), source } => write!(f, "parsing {}: {source}", path.display()),
            Self::Parse { path: None, source } => write!(f, "parsing capa rule: {source}"),
            Self::LimitExceeded => write!(f, "capa rule limit of {MAX_RULES} exceeded"),
        }
    }
}

impl std::error::Error for CapaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::LimitExceeded => None,
        }
    }
}

/// A parsed, file-scope capa rule reduced to the features rampage can evaluate.
pub struct CapaRule {
    pub name: String,
    pub namespace: String,
    pub authors: Vec<String>,
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
    /// Precomputed identifiers for the `Capability { id, name, category }` shape (owned, so a long-running loader
    /// does not leak).
    id: String,
    category: String,
    root: Node,
}

/// A set of loaded capa rules.
pub struct CapaRuleSet {
    rules: Vec<CapaRule>,
}

impl CapaRuleSet {
    pub fn rules(&self) -> &[CapaRule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// A node in the reduced match-statement tree. Features we cannot assess become `Unevaluable`.
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    /// `not` holds its (normally single) child statement; it matches when the child does not.
    Not(Vec<Node>),
    /// `optional` always matches; its satisfied children still contribute evidence.
    Optional(Vec<Node>),
    /// `N or more` matches when at least N children match.
    NOrMore(usize, Vec<Node>),
    Feature(Feature),
    /// A feature or sub-scope rampage cannot assess; never matches.
    Unevaluable,
}

/// A leaf feature rampage can evaluate. Import/api/export all compare against import names but keep distinct
/// labels so the emitted evidence names the original feature kind.
enum Feature {
    Import(String),
    Api(String),
    Export(String),
    StringExact(String),
    Substring(String),
    Section(String),
    /// `os`/`arch`/`format`: accepted as always true, contributing no evidence.
    Global,
}

/// Loads every `*.yml`/`*.yaml` rule under `dir` (recursively). Valid YAML that is not a usable file-scope rule
/// is skipped silently; only a YAML syntax error or an I/O failure returns `Err`.
pub fn load_capa_rules(dir: &Path) -> Result<CapaRuleSet, CapaError> {
    let mut paths = Vec::new();
    collect_rule_files(dir, &mut paths)?;
    paths.sort();

    let mut rules = Vec::new();
    for path in paths {
        let text = fs::read_to_string(&path).map_err(|source| CapaError::Io { path: path.clone(), source })?;
        let parsed = parse_rule(&text).map_err(|source| CapaError::Parse { path: Some(path.clone()), source })?;
        if let Some(rule) = parsed {
            if rules.len() >= MAX_RULES {
                return Err(CapaError::LimitExceeded);
            }
            rules.push(rule);
        }
    }
    Ok(CapaRuleSet { rules })
}

/// Parses one or more capa rules from a YAML string (documents may be separated by `---`). A malformed document
/// returns `Err`; valid documents that are not usable file-scope rules are skipped.
pub fn load_capa_rules_from_str(yaml: &str) -> Result<CapaRuleSet, CapaError> {
    let mut rules = Vec::new();
    for document in serde_yaml_ng::Deserializer::from_str(yaml) {
        let value = Value::deserialize(document).map_err(|source| CapaError::Parse { path: None, source })?;
        if let Some(rule) = rule_from_value(&value) {
            if rules.len() >= MAX_RULES {
                return Err(CapaError::LimitExceeded);
            }
            rules.push(rule);
        }
    }
    Ok(CapaRuleSet { rules })
}

/// Evaluates every loaded rule against the imports and strings, returning a `Capability` per matching rule.
pub fn detect_capa(rules: &CapaRuleSet, imports: &[String], strings: &[String]) -> Vec<Capability> {
    let norm_imports: Vec<String> = imports.iter().map(|name| names::import_stem(name)).collect();
    let ctx = Ctx { imports: &norm_imports, strings };
    let mut found = Vec::new();
    for rule in &rules.rules {
        let (matched, mut evidence) = eval(&rule.root, &ctx);
        if matched {
            evidence.dedup();
            found.push(Capability {
                id: Cow::Owned(rule.id.clone()),
                name: Cow::Owned(rule.name.clone()),
                category: Cow::Owned(rule.category.clone()),
                evidence,
            });
        }
    }
    found
}

struct Ctx<'a> {
    imports: &'a [String],
    strings: &'a [String],
}

/// Recursively finds rule files; symbolic-link cycles are avoided by only descending real directories.
fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CapaError> {
    let entries = fs::read_dir(dir).map_err(|source| CapaError::Io { path: dir.to_path_buf(), source })?;
    for entry in entries {
        let entry = entry.map_err(|source| CapaError::Io { path: dir.to_path_buf(), source })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| CapaError::Io { path: path.clone(), source })?;
        if file_type.is_dir() {
            collect_rule_files(&path, out)?;
        } else if file_type.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml") {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn parse_rule(text: &str) -> Result<Option<CapaRule>, serde_yaml_ng::Error> {
    let value: Value = serde_yaml_ng::from_str(text)?;
    Ok(rule_from_value(&value))
}

/// Builds a `CapaRule` from a parsed document, or `None` when it is not a usable file-scope rule.
fn rule_from_value(value: &Value) -> Option<CapaRule> {
    let rule = value.get("rule")?.as_mapping()?;
    let meta = rule.get("meta")?.as_mapping()?;

    if !is_file_scope(meta) {
        return None;
    }

    let name = meta.get("name").and_then(Value::as_str)?.to_string();
    let namespace = meta.get("namespace").and_then(Value::as_str).unwrap_or("").to_string();
    let authors = string_list(meta.get("authors"));
    let attack = string_list(meta.get("att&ck"));
    let mbc = string_list(meta.get("mbc"));

    let features = rule.get("features")?.as_sequence()?;
    let children = parse_children(features, 1);
    if children.is_empty() {
        return None;
    }
    let root = if children.len() == 1 { children.into_iter().next().unwrap() } else { Node::And(children) };

    let category_src = namespace.split('/').next().filter(|s| !s.is_empty()).unwrap_or("capa");
    Some(CapaRule { id: slug(&name), category: category_src.to_string(), name, namespace, authors, attack, mbc, root })
}

/// A rule is file-scope when its static scope is `file`, or when no scope is declared (we default to file and
/// document it). The new `scopes: {static, dynamic}` form is preferred; the legacy `scope:` string is a fallback.
fn is_file_scope(meta: &serde_yaml_ng::Mapping) -> bool {
    if let Some(scopes) = meta.get("scopes").and_then(Value::as_mapping) {
        return match scopes.get("static").and_then(Value::as_str) {
            Some(scope) => scope.eq_ignore_ascii_case("file"),
            None => false,
        };
    }
    match meta.get("scope").and_then(Value::as_str) {
        Some(scope) => scope.eq_ignore_ascii_case("file"),
        None => true,
    }
}

fn parse_children(seq: &[Value], depth: usize) -> Vec<Node> {
    seq.iter().map(|child| parse_node(child, depth)).collect()
}

fn parse_node(value: &Value, depth: usize) -> Node {
    if depth > MAX_DEPTH {
        return Node::Unevaluable;
    }
    let Some(mapping) = value.as_mapping() else {
        return Node::Unevaluable;
    };
    let Some((key, leaf_value)) = primary_entry(mapping) else {
        return Node::Unevaluable;
    };

    match key.as_str() {
        "and" => combinator(leaf_value, depth, Node::And),
        "or" => combinator(leaf_value, depth, Node::Or),
        "not" => combinator(leaf_value, depth, Node::Not),
        "optional" | "0 or more" => combinator(leaf_value, depth, Node::Optional),
        _ => {
            if let Some(n) = parse_n_or_more(&key) {
                return combinator(leaf_value, depth, move |children| Node::NOrMore(n, children));
            }
            parse_leaf(&key, leaf_value)
        }
    }
}

fn combinator(value: &Value, depth: usize, build: impl FnOnce(Vec<Node>) -> Node) -> Node {
    match value.as_sequence() {
        Some(seq) => {
            let children = parse_children(seq, depth + 1);
            if children.is_empty() { Node::Unevaluable } else { build(children) }
        }
        None => Node::Unevaluable,
    }
}

/// Parses `"N or more"` (N >= 1) into N; anything else is not a counted statement.
fn parse_n_or_more(key: &str) -> Option<usize> {
    let rest = key.strip_suffix(" or more")?;
    let n: usize = rest.trim().parse().ok()?;
    if n == 0 { None } else { Some(n) }
}

fn parse_leaf(key: &str, value: &Value) -> Node {
    let Some(text) = scalar_string(value) else {
        return Node::Unevaluable;
    };
    match key {
        "import" => Node::Feature(Feature::Import(text)),
        "api" => Node::Feature(Feature::Api(text)),
        "export" => Node::Feature(Feature::Export(text)),
        // capa `string` is an exact match; a `/regex/` form is outside this literal evaluator.
        "string" if is_regex(&text) => Node::Unevaluable,
        "string" => Node::Feature(Feature::StringExact(text)),
        "substring" => Node::Feature(Feature::Substring(text)),
        "section" => Node::Feature(Feature::Section(text)),
        "os" | "arch" | "format" => Node::Feature(Feature::Global),
        _ => Node::Unevaluable,
    }
}

fn is_regex(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.len() >= 2 && trimmed.starts_with('/') && trimmed.ends_with('/')
}

/// Returns the statement/feature key and its value, ignoring the `description`/`comment` annotations that may
/// accompany a node.
fn primary_entry(mapping: &serde_yaml_ng::Mapping) -> Option<(String, &Value)> {
    for (key, value) in mapping {
        let key = key.as_str()?;
        if key == "description" || key == "comment" {
            continue;
        }
        return Some((key.to_string(), value));
    }
    None
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    match value.and_then(Value::as_sequence) {
        Some(seq) => seq.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        None => Vec::new(),
    }
}

/// Evaluates a node, returning whether it matched and the evidence from the branches that contributed.
fn eval(node: &Node, ctx: &Ctx) -> (bool, Vec<String>) {
    match node {
        Node::Unevaluable => (false, Vec::new()),
        Node::Feature(feature) => eval_feature(feature, ctx),
        Node::And(children) => {
            let mut evidence = Vec::new();
            for child in children {
                let (matched, child_evidence) = eval(child, ctx);
                if !matched {
                    return (false, Vec::new());
                }
                evidence.extend(child_evidence);
            }
            (true, evidence)
        }
        Node::Or(children) => {
            let mut matched_any = false;
            let mut evidence = Vec::new();
            for child in children {
                let (matched, child_evidence) = eval(child, ctx);
                if matched {
                    matched_any = true;
                    evidence.extend(child_evidence);
                }
            }
            (matched_any, evidence)
        }
        Node::Not(children) => {
            // Matches when the (normally single) child statement does not; its inner matches are not evidence.
            let matched_inner = children.iter().all(|child| eval(child, ctx).0);
            (!matched_inner, Vec::new())
        }
        Node::Optional(children) => {
            let mut evidence = Vec::new();
            for child in children {
                let (matched, child_evidence) = eval(child, ctx);
                if matched {
                    evidence.extend(child_evidence);
                }
            }
            (true, evidence)
        }
        Node::NOrMore(n, children) => {
            let mut count = 0;
            let mut evidence = Vec::new();
            for child in children {
                let (matched, child_evidence) = eval(child, ctx);
                if matched {
                    count += 1;
                    evidence.extend(child_evidence);
                }
            }
            (count >= *n, evidence)
        }
    }
}

fn eval_feature(feature: &Feature, ctx: &Ctx) -> (bool, Vec<String>) {
    match feature {
        Feature::Import(value) => symbol_match("import", value, ctx),
        Feature::Api(value) => symbol_match("api", value, ctx),
        Feature::Export(value) => symbol_match("export", value, ctx),
        Feature::StringExact(value) => {
            let hit = ctx.strings.iter().any(|s| s == value);
            evidence_if(hit, "string", value)
        }
        Feature::Substring(value) => {
            let hit = ctx.strings.iter().any(|s| s.contains(value));
            evidence_if(hit, "substring", value)
        }
        Feature::Section(value) => {
            // rampage is not given a section list here, so a section name is matched against the strings input.
            let hit = ctx.strings.iter().any(|s| s.eq_ignore_ascii_case(value));
            evidence_if(hit, "section", value)
        }
        Feature::Global => (true, Vec::new()),
    }
}

fn symbol_match(kind: &str, value: &str, ctx: &Ctx) -> (bool, Vec<String>) {
    let needle = normalize_symbol(value);
    let hit = ctx.imports.iter().any(|name| name == &needle);
    evidence_if(hit, kind, value)
}

fn evidence_if(hit: bool, kind: &str, value: &str) -> (bool, Vec<String>) {
    if hit { (true, vec![format!("{kind}:{value}")]) } else { (false, Vec::new()) }
}

/// Normalizes a capa api/import/export name to compare with normalized import names: the module prefix
/// (`kernel32.CreateFileW`) is dropped and the crate's import normalization is applied.
fn normalize_symbol(raw: &str) -> String {
    let symbol = raw.rsplit('.').next().unwrap_or(raw);
    names::import_stem(symbol)
}

fn slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() { "capa-rule".to_string() } else { trimmed.to_string() }
}

#[cfg(test)]
mod tests;
