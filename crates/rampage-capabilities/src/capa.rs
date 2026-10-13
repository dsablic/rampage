//! Imports Mandiant capa rules (github.com/mandiant/capa-rules, Apache-2.0) as a capability source.
//!
//! capa rules are a large curated behavior corpus. This module parses their YAML and evaluates the SUBSET of
//! features rampage can assess from imports, exports and strings alone, emitting the crate's `Capability` shape.
//! It is a deliberately partial evaluator -- NOT a reimplementation of capa -- so matches remain triage-grade
//! evidence.
//!
//! Supported statements: `and`, `or`, `not`, `optional`, and `N or more`; `description:`/`comment:` items inside
//! a statement list are annotations and are dropped. Supported leaf features:
//! - `import`/`api`: compared with import names by [`names::stem_matches`] after [`names::import_stem`], on the
//!   symbol after any module qualifier (`kernel32.CreateFile` is matched as `createfile`, from any DLL). A
//!   charset-neutral name matches both `A` and `W` variants, as capa's own feature extractor does;
//! - `export`: compared the same way with export names, when [`detect_capa_with_exports`] supplies them;
//! - `string` (exact), `substring` (contains), and `section` (matched against the provided strings, since
//!   rampage is not given a section list here);
//! - the globals `os`/`arch`/`format`: satisfiable but evidence-free, because no target context is supplied.
//!
//! Every other feature is UN-EVALUABLE, a third outcome next to matched and not matched: an `and` with an
//! un-evaluable child cannot match, an `or` ignores it, `N or more` counts it as neither, and a `not` over an
//! un-evaluable subtree is itself un-evaluable (absence of something we cannot see is not evidence). This covers:
//!   - non-file features we cannot assess from imports/strings: `bytes`, `number`, `offset`, `mnemonic`,
//!     `characteristic`, `operand`, `property`, and any `count(...)` feature;
//!   - `match:` references to other rules (we have no rule-match graph);
//!   - `string:` written as a `/regex/` or `/regex/i`: only literal matching is done;
//!   - ordinal imports (`ws2_32.#23`): import names carry no ordinal or module here;
//!   - `export` when no export list is supplied;
//!   - sub-scope statements `function` / `basic block` / `instruction` / `call` / `process` / `thread` /
//!     `span of calls` and their subtrees.
//!
//! Whole rules are skipped when their static scope is not `file` (a rule declaring no scope defaults to
//! `function`, as in capa), and when no feature outside a `not` can supply evidence. A rule is reported only
//! when it matches with at least one piece of evidence.

use std::borrow::Cow;
use std::collections::HashSet;
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
    /// `capa/<namespace>/<name>` slugs, made unique within the rule set (owned, so a long-running loader does not
    /// leak). The `capa/` prefix keeps them apart from the built-in rule ids.
    id: String,
    category: String,
    root: Node,
}

/// A set of loaded capa rules.
pub struct CapaRuleSet {
    rules: Vec<CapaRule>,
}

impl CapaRuleSet {
    fn new(mut rules: Vec<CapaRule>) -> Self {
        let mut taken = HashSet::new();
        for rule in &mut rules {
            let mut id = rule.id.clone();
            let mut suffix = 1;
            while !taken.insert(id.clone()) {
                suffix += 1;
                id = format!("{}-{suffix}", rule.id);
            }
            rule.id = id;
        }
        CapaRuleSet { rules }
    }

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
    /// A feature or sub-scope rampage cannot assess.
    Unevaluable,
}

/// A leaf feature rampage can evaluate. Import and api both compare against import names but keep distinct
/// labels so the emitted evidence names the original feature kind.
enum Feature {
    Import(String),
    Api(String),
    Export(String),
    StringExact(String),
    Substring(String),
    Section(String),
    /// `os`/`arch`/`format`: satisfiable without contributing evidence.
    Global,
}

/// The three-valued result of evaluating a node.
enum Outcome {
    Matched(Vec<String>),
    Missed,
    Unknown,
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
        push_rule(&mut rules, &path, &text)?;
    }
    Ok(CapaRuleSet::new(rules))
}

/// Parses one rule per `(path, text)` file already read by the caller, as [`load_capa_rules`] does for the files
/// it finds; the paths only name the files in errors.
pub fn load_capa_rule_texts<'a>(
    files: impl IntoIterator<Item = (&'a Path, &'a str)>,
) -> Result<CapaRuleSet, CapaError> {
    let mut rules = Vec::new();
    for (path, text) in files {
        push_rule(&mut rules, path, text)?;
    }
    Ok(CapaRuleSet::new(rules))
}

fn push_rule(rules: &mut Vec<CapaRule>, path: &Path, text: &str) -> Result<(), CapaError> {
    let parsed = parse_rule(text).map_err(|source| CapaError::Parse { path: Some(path.to_path_buf()), source })?;
    if let Some(rule) = parsed {
        if rules.len() >= MAX_RULES {
            return Err(CapaError::LimitExceeded);
        }
        rules.push(rule);
    }
    Ok(())
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
    Ok(CapaRuleSet::new(rules))
}

/// Evaluates every loaded rule against the imports and strings, returning a `Capability` per matching rule.
/// `export` features are un-evaluable here; see [`detect_capa_with_exports`].
pub fn detect_capa(rules: &CapaRuleSet, imports: &[String], strings: &[String]) -> Vec<Capability> {
    evaluate(rules, imports, None, strings)
}

/// [`detect_capa`] with the binary's export names, so `export` features are evaluated too.
pub fn detect_capa_with_exports(
    rules: &CapaRuleSet,
    imports: &[String],
    exports: &[String],
    strings: &[String],
) -> Vec<Capability> {
    evaluate(rules, imports, Some(exports), strings)
}

fn evaluate(
    rules: &CapaRuleSet,
    imports: &[String],
    exports: Option<&[String]>,
    strings: &[String],
) -> Vec<Capability> {
    let stems = |names: &[String]| names.iter().map(|name| names::import_stem(name)).collect::<Vec<_>>();
    let imports = stems(imports);
    let exports = exports.map(stems);
    let ctx = Ctx { imports: &imports, exports: exports.as_deref(), strings };
    let mut found = Vec::new();
    for rule in &rules.rules {
        let Outcome::Matched(evidence) = eval(&rule.root, &ctx) else {
            continue;
        };
        let mut seen = HashSet::new();
        let evidence: Vec<String> = evidence.into_iter().filter(|entry| seen.insert(entry.clone())).collect();
        if evidence.is_empty() {
            continue;
        }
        found.push(Capability {
            id: Cow::Owned(rule.id.clone()),
            name: Cow::Owned(rule.name.clone()),
            category: Cow::Owned(rule.category.clone()),
            evidence,
        });
    }
    found
}

struct Ctx<'a> {
    /// [`names::import_stem`] of each import.
    imports: &'a [String],
    /// [`names::import_stem`] of each export, when the caller supplied exports.
    exports: Option<&'a [String]>,
    strings: &'a [String],
}

/// Recursively finds rule files. Symbolic links (to files or directories) are not followed, which also rules out
/// link cycles.
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
    if !can_supply_evidence(&root) {
        return None;
    }

    let category_src = namespace.split('/').next().filter(|s| !s.is_empty()).unwrap_or("capa");
    Some(CapaRule {
        id: rule_id(&namespace, &name),
        category: category_src.to_string(),
        name,
        namespace,
        authors,
        attack,
        mbc,
        root,
    })
}

/// Whether some evaluable, evidence-bearing feature sits outside every `not`, so the rule can ever be reported.
fn can_supply_evidence(node: &Node) -> bool {
    match node {
        Node::And(children) | Node::Or(children) | Node::Optional(children) | Node::NOrMore(_, children) => {
            children.iter().any(can_supply_evidence)
        }
        Node::Not(_) | Node::Unevaluable | Node::Feature(Feature::Global) => false,
        Node::Feature(_) => true,
    }
}

/// A rule is file-scope when its static scope is `file`. The `scopes: {static, dynamic}` form is preferred; the
/// legacy `scope:` string is a fallback, and a rule declaring neither defaults to capa's `function` scope.
fn is_file_scope(meta: &serde_yaml_ng::Mapping) -> bool {
    if let Some(scopes) = meta.get("scopes").and_then(Value::as_mapping) {
        return scopes.get("static").and_then(Value::as_str).is_some_and(|scope| scope.eq_ignore_ascii_case("file"));
    }
    meta.get("scope").and_then(Value::as_str).is_some_and(|scope| scope.eq_ignore_ascii_case("file"))
}

/// Parses statement children, dropping `description:`/`comment:`-only items, which annotate the list rather than
/// add a condition to it.
fn parse_children(seq: &[Value], depth: usize) -> Vec<Node> {
    seq.iter().filter(|child| !is_annotation(child)).map(|child| parse_node(child, depth)).collect()
}

fn is_annotation(value: &Value) -> bool {
    value.as_mapping().is_some_and(|mapping| {
        !mapping.is_empty() && mapping.keys().all(|key| matches!(key.as_str(), Some("description" | "comment")))
    })
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
        "import" | "api" | "export" if symbol_part(&text).starts_with('#') => Node::Unevaluable,
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

/// Whether `text` is a capa regex: `/pattern/` or the case-insensitive `/pattern/i`.
fn is_regex(text: &str) -> bool {
    // capa's own parser recognizes exactly these two shapes; `/usr/bin` stays a literal path.
    text.trim().strip_prefix('/').is_some_and(|body| body.ends_with('/') || body.ends_with("/i"))
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

/// Conjunction of `children`: missed if any child is missed, otherwise unknown if any child is unknown.
fn eval_all(children: &[Node], ctx: &Ctx) -> Outcome {
    let mut evidence = Vec::new();
    let mut unknown = false;
    for child in children {
        match eval(child, ctx) {
            Outcome::Matched(child_evidence) => evidence.extend(child_evidence),
            Outcome::Missed => return Outcome::Missed,
            Outcome::Unknown => unknown = true,
        }
    }
    if unknown { Outcome::Unknown } else { Outcome::Matched(evidence) }
}

/// Evaluates a node, returning the evidence from the branches that contributed when it matched.
fn eval(node: &Node, ctx: &Ctx) -> Outcome {
    match node {
        Node::Unevaluable => Outcome::Unknown,
        Node::Feature(feature) => eval_feature(feature, ctx),
        Node::And(children) => eval_all(children, ctx),
        Node::Or(children) => {
            let (evidence, matched, unknown) = tally(children, ctx);
            if matched > 0 {
                Outcome::Matched(evidence)
            } else if unknown > 0 {
                Outcome::Unknown
            } else {
                Outcome::Missed
            }
        }
        // Matches when the (normally single) child statement does not; its inner matches are not evidence.
        Node::Not(children) => match eval_all(children, ctx) {
            Outcome::Matched(_) => Outcome::Missed,
            Outcome::Missed => Outcome::Matched(Vec::new()),
            Outcome::Unknown => Outcome::Unknown,
        },
        Node::Optional(children) => Outcome::Matched(tally(children, ctx).0),
        Node::NOrMore(n, children) => {
            let (evidence, matched, unknown) = tally(children, ctx);
            if matched >= *n {
                Outcome::Matched(evidence)
            } else if matched + unknown >= *n {
                Outcome::Unknown
            } else {
                Outcome::Missed
            }
        }
    }
}

/// Evaluates every child: the matched children's evidence and the matched and unknown counts.
fn tally(children: &[Node], ctx: &Ctx) -> (Vec<String>, usize, usize) {
    let (mut evidence, mut matched, mut unknown) = (Vec::new(), 0, 0);
    for child in children {
        match eval(child, ctx) {
            Outcome::Matched(child_evidence) => {
                matched += 1;
                evidence.extend(child_evidence);
            }
            Outcome::Missed => {}
            Outcome::Unknown => unknown += 1,
        }
    }
    (evidence, matched, unknown)
}

fn eval_feature(feature: &Feature, ctx: &Ctx) -> Outcome {
    match feature {
        Feature::Import(value) => symbol_match("import", value, ctx.imports),
        Feature::Api(value) => symbol_match("api", value, ctx.imports),
        Feature::Export(value) => match ctx.exports {
            Some(exports) => symbol_match("export", value, exports),
            None => Outcome::Unknown,
        },
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
        Feature::Global => Outcome::Matched(Vec::new()),
    }
}

/// Matches a capa symbol against stems: the module qualifier (`kernel32.`) is dropped and the remaining name is
/// a charset-neutral [`names::stem_matches`] pattern.
fn symbol_match(kind: &str, value: &str, stems: &[String]) -> Outcome {
    let pattern = names::import_stem(symbol_part(value));
    let hit = stems.iter().any(|stem| names::stem_matches(&pattern, stem));
    evidence_if(hit, kind, value)
}

/// The symbol of a possibly module-qualified capa name (`kernel32.CreateFileW` -> `CreateFileW`).
fn symbol_part(raw: &str) -> &str {
    raw.rsplit('.').next().unwrap_or(raw)
}

fn evidence_if(hit: bool, kind: &str, value: &str) -> Outcome {
    if hit { Outcome::Matched(vec![format!("{kind}:{value}")]) } else { Outcome::Missed }
}

fn rule_id(namespace: &str, name: &str) -> String {
    let mut id = String::from("capa");
    for part in namespace.split('/').map(slug).filter(|part| !part.is_empty()) {
        id.push('/');
        id.push_str(&part);
    }
    id.push('/');
    let name = slug(name);
    id.push_str(if name.is_empty() { "rule" } else { &name });
    id
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
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests;
