//! A thin wrapper over VirusTotal's pure-Rust `yara-x` engine for running user-supplied YARA rules against a
//! loaded binary. We bundle only the engine: rules are always provided by the caller. The public surface is
//! intentionally small -- compile rules from text/files, scan bytes or a [`rampage_loaders::Binary`], and get
//! back owned, `serde`-serializable results that a later API/MCP layer can hand out directly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rampage_loaders::Binary;
use serde::Serialize;

/// Cap on matched-string instances recorded per rule. A pathological pattern (e.g. a single byte with many hits)
/// can match thousands of times; we keep the result bounded so callers never face unbounded output. The cap is
/// per rule, across all of its patterns.
pub const MAX_MATCHED_STRINGS_PER_RULE: usize = 64;

/// Errors from compiling or scanning. Wraps `yara-x`'s own errors as rendered strings so they cross the API
/// boundary without leaking the dependency's types or ever panicking.
#[derive(Debug, thiserror::Error)]
pub enum YaraError {
    #[error("cannot read {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("no .yar or .yara rule files in {0}")]
    NoRuleFiles(PathBuf),
    #[error("rule compilation failed: {0}")]
    Compile(String),
    #[error("scan failed: {0}")]
    Scan(String),
}

/// A compiled set of YARA rules, ready to scan with. Opaque wrapper over `yara_x::Rules`.
pub struct Rules {
    inner: yara_x::Rules,
}

/// One pattern (string) instance that matched, located within the scanned data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchedString {
    /// The pattern's identifier within its rule, e.g. `$a`.
    pub identifier: String,
    /// Byte offset of the match within the scanned data.
    pub offset: usize,
    /// Length in bytes of the matched region.
    pub length: usize,
}

/// A rule that matched during a scan, with its metadata, tags and a bounded list of matched strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct YaraMatch {
    pub identifier: String,
    pub namespace: String,
    pub tags: Vec<String>,
    /// Rule metadata as `name -> value`, each value rendered to a string.
    pub metadata: BTreeMap<String, String>,
    /// Matched pattern instances, capped at [`MAX_MATCHED_STRINGS_PER_RULE`].
    pub matched_strings: Vec<MatchedString>,
}

/// Compile one or more YARA rules from a single source string.
pub fn compile(sources: &str) -> Result<Rules, YaraError> {
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(sources).map_err(|e| YaraError::Compile(e.to_string()))?;
    Ok(Rules { inner: compiler.build() })
}

/// Compile rules from a set of files, tagging each with its path so compile errors name the source file.
pub fn compile_files<P: AsRef<Path>>(paths: &[P]) -> Result<Rules, YaraError> {
    // Read every file first and keep the text alive for the whole build: `SourceCode` borrows it.
    let mut sources: Vec<(String, String)> = Vec::with_capacity(paths.len());
    for path in paths {
        let path = path.as_ref();
        let text =
            std::fs::read_to_string(path).map_err(|source| YaraError::Io { path: path.to_path_buf(), source })?;
        sources.push((path.display().to_string(), text));
    }
    let mut compiler = yara_x::Compiler::new();
    for (origin, text) in &sources {
        let code = yara_x::SourceCode::from(text.as_str()).with_origin(origin);
        compiler.add_source(code).map_err(|e| YaraError::Compile(e.to_string()))?;
    }
    Ok(Rules { inner: compiler.build() })
}

/// Compile every `.yar`/`.yara` file in a directory (non-recursive), in sorted path order for stable results. A
/// directory with no such file is an error rather than an empty rule set that silently matches nothing.
pub fn compile_dir<P: AsRef<Path>>(dir: P) -> Result<Rules, YaraError> {
    let dir = dir.as_ref();
    let mut paths: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|source| YaraError::Io { path: dir.to_path_buf(), source })?;
    for entry in entries {
        let entry = entry.map_err(|source| YaraError::Io { path: dir.to_path_buf(), source })?;
        let path = entry.path();
        if matches!(path.extension().and_then(|e| e.to_str()), Some("yar" | "yara")) {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        return Err(YaraError::NoRuleFiles(dir.to_path_buf()));
    }
    paths.sort();
    compile_files(&paths)
}

/// Scan raw bytes, returning the rules that matched.
pub fn scan(rules: &Rules, data: &[u8]) -> Result<Vec<YaraMatch>, YaraError> {
    let mut scanner = yara_x::Scanner::new(&rules.inner);
    let results = scanner.scan(data).map_err(|e| YaraError::Scan(e.to_string()))?;
    Ok(results.matching_rules().map(to_match).collect())
}

/// Scan a loaded binary's in-memory image (`binary.image_bytes()`).
pub fn scan_binary(rules: &Rules, binary: &Binary) -> Result<Vec<YaraMatch>, YaraError> {
    scan(rules, binary.image_bytes())
}

/// Convert a `yara-x` matching rule into our owned, serializable form, bounding the matched-string list.
fn to_match(rule: yara_x::Rule) -> YaraMatch {
    let tags = rule.tags().map(|t| t.identifier().to_string()).collect();
    let metadata = rule.metadata().map(|(name, value)| (name.to_string(), meta_to_string(value))).collect();

    let mut matched_strings = Vec::new();
    'patterns: for pattern in rule.patterns() {
        let identifier = pattern.identifier().to_string();
        for m in pattern.matches() {
            if matched_strings.len() >= MAX_MATCHED_STRINGS_PER_RULE {
                break 'patterns;
            }
            let range = m.range();
            let identifier = identifier.clone();
            matched_strings.push(MatchedString { identifier, offset: range.start, length: range.len() });
        }
    }

    YaraMatch {
        identifier: rule.identifier().to_string(),
        namespace: rule.namespace().to_string(),
        tags,
        metadata,
        matched_strings,
    }
}

/// Render a metadata value to a string for the `name -> value` map.
fn meta_to_string(value: yara_x::MetaValue) -> String {
    match value {
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f) => f.to_string(),
        yara_x::MetaValue::Bool(b) => b.to_string(),
        yara_x::MetaValue::String(s) => s.to_string(),
        yara_x::MetaValue::Bytes(b) => b.to_string(),
    }
}
