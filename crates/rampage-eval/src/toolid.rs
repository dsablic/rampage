//! Producing-tool identification (`rampage_detect`, what `detect_tools` reports) scored against binaries whose
//! toolchain is known from how they were built.
//!
//! Every answer is a `(kind, name)` pair per binary. An expected pair that is detected is correct, one that is
//! not is missed, and a detected pair the truth does not expect is spurious. A detection cannot be wrong: a
//! binary can carry several compilers' marks (a C frontend and the toolchain that drove it), so a second compiler
//! name is an extra claim, not a contradicted one.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use rampage_detect::Kind;
use rampage_loaders::Binary;
use serde::{Deserialize, Serialize};

use crate::{Outcome, Report, ratio};

/// The kinds a tool truth may name: every [`Kind`] a build can be known to involve (all but `unknown`).
pub const TOOL_KINDS: [&str; 6] = ["compiler", "linker", "runtime", "packer", "protector", "installer"];

/// One tool a build is known to have used, and how that is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedTool {
    pub kind: String,
    pub name: String,
    pub why: String,
}

/// A way of building, shared by every binary built that way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    /// The commands, as the build scripts run them.
    pub how: String,
    pub expected: Vec<ExpectedTool>,
    /// Kinds the build certainly did not involve (no build script runs a packer), so any detection of one is a
    /// false positive however strong its evidence.
    pub absent: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBinary {
    pub toolchain: String,
    /// The script that builds it (or where it came from).
    pub built: String,
}

/// Which tools produced each scored binary, keyed by path (relative to the truth file).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTruth {
    pub toolchains: BTreeMap<String, Toolchain>,
    pub binaries: BTreeMap<String, ToolBinary>,
    /// Committed binaries left out, each with the reason (an unrecorded build, a format nothing loads).
    #[serde(default)]
    pub excluded: BTreeMap<String, String>,
}

impl ToolTruth {
    /// Parses and checks a truth: every binary names a defined toolchain, every toolchain is used, kinds are
    /// [`TOOL_KINDS`], no expected pair repeats, and no kind is both expected and absent.
    pub fn from_json(text: &str) -> Result<ToolTruth, String> {
        let truth: ToolTruth = serde_json::from_str(text).map_err(|error| error.to_string())?;
        for (path, binary) in &truth.binaries {
            if !truth.toolchains.contains_key(&binary.toolchain) {
                return Err(format!("{path}: unknown toolchain {:?}", binary.toolchain));
            }
            if truth.excluded.contains_key(path) {
                return Err(format!("{path} is both scored and excluded"));
            }
        }
        let kind = |kind: &str, at: &str| {
            if TOOL_KINDS.contains(&kind) { Ok(()) } else { Err(format!("{at}: unknown kind {kind:?}")) }
        };
        for (name, toolchain) in &truth.toolchains {
            if !truth.binaries.values().any(|binary| &binary.toolchain == name) {
                return Err(format!("toolchain {name} is not used by any binary"));
            }
            let mut seen = BTreeSet::new();
            for tool in &toolchain.expected {
                kind(&tool.kind, name)?;
                if !seen.insert((tool.kind.as_str(), tool.name.as_str())) {
                    return Err(format!("{name}: {} {} is expected twice", tool.kind, tool.name));
                }
                if toolchain.absent.contains(&tool.kind) {
                    return Err(format!("{name}: {} is both expected and absent", tool.kind));
                }
            }
            for absent in &toolchain.absent {
                kind(absent, name)?;
            }
        }
        Ok(truth)
    }
}

/// One tool a detector reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedTool {
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// The truth's spelling of a detection kind (the same as its JSON form).
pub fn kind_tag(kind: Kind) -> &'static str {
    match kind {
        Kind::Packer => "packer",
        Kind::Compiler => "compiler",
        Kind::Protector => "protector",
        Kind::Installer => "installer",
        Kind::Linker => "linker",
        Kind::Cryptor => "cryptor",
        Kind::Joiner => "joiner",
        Kind::Sfx => "sfx",
        Kind::Runtime => "runtime",
        Kind::Unknown => "unknown",
    }
}

/// What `detect_tools` reports for `binary` without a user PeID database: the bundled signatures only.
pub fn detected_tools(binary: &Binary) -> Vec<DetectedTool> {
    rampage_detect::identify(binary, &rampage_detect::SignatureDb::bundled())
        .into_iter()
        .map(|detection| DetectedTool {
            kind: kind_tag(detection.kind).to_owned(),
            name: detection.name,
            evidence: detection.evidence,
        })
        .collect()
}

/// One binary's tool where the detector and the truth do not agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDisagreement {
    pub binary: String,
    pub kind: String,
    pub name: String,
    pub outcome: Outcome,
    /// What fired, for a spurious detection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// How the truth knows: why a missed tool was used, or that a spurious kind was absent from the build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

impl ToolDisagreement {
    pub(crate) fn order(&self, other: &Self) -> Ordering {
        (&self.binary, &self.kind, &self.name).cmp(&(&other.binary, &other.kind, &other.name))
    }
}

/// Scores `detections` (keyed like [`ToolTruth::binaries`]) against `truth`. A truth binary with no entry in
/// `detections` had nothing detected; a detection for a binary the truth does not score is ignored.
pub fn score_tools(detections: &BTreeMap<String, Vec<DetectedTool>>, truth: &ToolTruth) -> Report {
    let (mut correct, mut missed, mut spurious) = (0, 0, 0);
    let mut disagreements = Vec::new();
    for (path, binary) in &truth.binaries {
        let Some(toolchain) = truth.toolchains.get(&binary.toolchain) else { continue };
        let found: BTreeMap<(&str, &str), &DetectedTool> = detections
            .get(path)
            .into_iter()
            .flatten()
            .map(|tool| ((tool.kind.as_str(), tool.name.as_str()), tool))
            .collect();
        let expected: BTreeSet<(&str, &str)> =
            toolchain.expected.iter().map(|tool| (tool.kind.as_str(), tool.name.as_str())).collect();
        for tool in &toolchain.expected {
            if found.contains_key(&(tool.kind.as_str(), tool.name.as_str())) {
                correct += 1;
                continue;
            }
            missed += 1;
            disagreements.push(ToolDisagreement {
                binary: path.clone(),
                kind: tool.kind.clone(),
                name: tool.name.clone(),
                outcome: Outcome::Missed,
                evidence: Vec::new(),
                why: Some(tool.why.clone()),
            });
        }
        for (key, tool) in found {
            if expected.contains(&key) {
                continue;
            }
            spurious += 1;
            let absent = toolchain.absent.contains(&tool.kind);
            disagreements.push(ToolDisagreement {
                binary: path.clone(),
                kind: tool.kind.clone(),
                name: tool.name.clone(),
                outcome: Outcome::Spurious,
                evidence: tool.evidence.clone(),
                why: absent.then(|| format!("the build used no {}: {}", tool.kind, toolchain.how)),
            });
        }
    }
    disagreements.sort_by(ToolDisagreement::order);
    Report {
        precision: ratio(correct, correct + spurious),
        recall: ratio(correct, correct + missed),
        correct,
        wrong: 0,
        missed,
        spurious,
        disagreements: Vec::new(),
        tool_disagreements: disagreements,
        disagreement_classes: BTreeMap::new(),
        omitted: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUTH: &str = r#"{
        "toolchains": {
            "zig-musl": {
                "how": "zig cc -target x86_64-linux-musl",
                "expected": [
                    {"kind": "compiler", "name": "Clang/LLVM", "why": "zig cc compiles C with clang"},
                    {"kind": "linker", "name": "LLD", "why": "zig links ELF with LLD"},
                    {"kind": "runtime", "name": "musl", "why": "the musl target links static musl"}
                ],
                "absent": ["packer"]
            },
            "go": {
                "how": "go build",
                "expected": [{"kind": "compiler", "name": "Go", "why": "go build"}],
                "absent": ["packer"]
            }
        },
        "binaries": {
            "a.elf": {"toolchain": "zig-musl", "built": "build.sh"},
            "b.elf": {"toolchain": "go", "built": "build.sh"}
        },
        "excluded": {"c.lib": "an archive"}
    }"#;

    fn tool(kind: &str, name: &str) -> DetectedTool {
        DetectedTool { kind: kind.to_owned(), name: name.to_owned(), evidence: vec![format!("{name} evidence")] }
    }

    fn with(text: &str, from: &str, to: &str) -> Result<ToolTruth, String> {
        assert!(text.contains(from), "{from}");
        ToolTruth::from_json(&text.replacen(from, to, 1))
    }

    #[test]
    fn score_counts_detected_missed_and_extra_tools_per_binary() {
        let truth = ToolTruth::from_json(TRUTH).unwrap();
        let detections = BTreeMap::from([
            (
                "a.elf".to_owned(),
                vec![
                    tool("compiler", "Clang/LLVM"),
                    tool("linker", "LLD"),
                    tool("packer", "UPX"),
                    tool("linker", "LLD"),
                ],
            ),
            ("b.elf".to_owned(), vec![tool("compiler", "Go"), tool("compiler", "Zig")]),
            ("elsewhere.elf".to_owned(), vec![tool("packer", "UPX")]),
        ]);
        let report = score_tools(&detections, &truth);
        assert_eq!((report.correct, report.wrong, report.missed, report.spurious), (3, 0, 1, 2));
        assert!((report.precision - 0.6).abs() < 1e-12);
        assert!((report.recall - 0.75).abs() < 1e-12);
        assert!(report.disagreements.is_empty());
        let entries: Vec<(&str, &str, Outcome)> = report
            .tool_disagreements
            .iter()
            .map(|entry| (entry.binary.as_str(), entry.name.as_str(), entry.outcome))
            .collect();
        assert_eq!(
            entries,
            [
                ("a.elf", "UPX", Outcome::Spurious),
                ("a.elf", "musl", Outcome::Missed),
                ("b.elf", "Zig", Outcome::Spurious)
            ]
        );
        let [packer, runtime, zig] = &report.tool_disagreements[..] else { unreachable!() };
        assert_eq!(packer.evidence, ["UPX evidence"]);
        assert_eq!(packer.why.as_deref(), Some("the build used no packer: zig cc -target x86_64-linux-musl"));
        assert_eq!(runtime.why.as_deref(), Some("the musl target links static musl"));
        assert!(runtime.evidence.is_empty());
        // Not expected, but not a kind the truth rules out either.
        assert_eq!(zig.why, None);
    }

    #[test]
    fn a_binary_without_detections_misses_everything_it_expects() {
        let truth = ToolTruth::from_json(TRUTH).unwrap();
        let report = score_tools(&BTreeMap::new(), &truth);
        assert_eq!((report.correct, report.missed, report.spurious), (0, 4, 0));
        assert_eq!((report.precision, report.recall), (0.0, 0.0));
    }

    #[test]
    fn truncation_keeps_missed_tools_before_spurious_ones_and_round_trips() {
        let truth = ToolTruth::from_json(TRUTH).unwrap();
        let detections = BTreeMap::from([("a.elf".to_owned(), vec![tool("packer", "UPX"), tool("compiler", "Zig")])]);
        let mut report = score_tools(&detections, &truth);
        assert_eq!((report.missed, report.spurious), (4, 2));
        report.truncate_disagreements(5);
        let kept: Vec<(&str, Outcome)> =
            report.tool_disagreements.iter().map(|entry| (entry.name.as_str(), entry.outcome)).collect();
        assert_eq!(
            kept,
            [
                ("Clang/LLVM", Outcome::Missed),
                ("Zig", Outcome::Spurious),
                ("LLD", Outcome::Missed),
                ("musl", Outcome::Missed),
                ("Go", Outcome::Missed),
            ]
        );
        assert_eq!(report.omitted, 1);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("\"evidence\":[]") && !json.contains("\"why\":null"), "{json}");
        assert_eq!(serde_json::from_str::<Report>(&json).unwrap(), report);
    }

    #[test]
    fn same_name_under_another_kind_is_not_a_match() {
        let truth = ToolTruth::from_json(TRUTH).unwrap();
        let detections = BTreeMap::from([("b.elf".to_owned(), vec![tool("linker", "Go")])]);
        let report = score_tools(&detections, &truth);
        assert_eq!((report.correct, report.missed, report.spurious), (0, 4, 1));
    }

    #[test]
    fn truth_rejects_inconsistent_entries() {
        assert!(ToolTruth::from_json(TRUTH).is_ok());
        let unknown = with(TRUTH, r#""toolchain": "go""#, r#""toolchain": "rustc""#).unwrap_err();
        assert!(unknown.contains("unknown toolchain \"rustc\""), "{unknown}");
        let kind = with(TRUTH, r#""kind": "runtime""#, r#""kind": "runtimes""#).unwrap_err();
        assert!(kind.contains("unknown kind \"runtimes\""), "{kind}");
        let absent = with(TRUTH, r#""absent": ["packer"]"#, r#""absent": ["compiler"]"#).unwrap_err();
        assert!(absent.contains("compiler is both expected and absent"), "{absent}");
        let bad_absent = with(TRUTH, r#""absent": ["packer"]"#, r#""absent": ["packers"]"#).unwrap_err();
        assert!(bad_absent.contains("unknown kind \"packers\""), "{bad_absent}");
        let twice = with(TRUTH, r#""name": "LLD""#, r#""name": "Clang/LLVM""#);
        assert!(twice.is_ok(), "a name may repeat under another kind");
        let twice = with(TRUTH, r#""kind": "linker", "name": "LLD""#, r#""kind": "compiler", "name": "Clang/LLVM""#);
        assert!(twice.unwrap_err().contains("Clang/LLVM is expected twice"));
        let unused = with(TRUTH, r#""toolchain": "go""#, r#""toolchain": "zig-musl""#).unwrap_err();
        assert!(unused.contains("toolchain go is not used"), "{unused}");
        let both = with(TRUTH, r#""c.lib""#, r#""b.elf""#).unwrap_err();
        assert!(both.contains("b.elf is both scored and excluded"), "{both}");
        let typo = with(TRUTH, r#""built": "build.sh"}"#, r#""built": "build.sh", "bulit": "x"}"#).unwrap_err();
        assert!(typo.contains("unknown field"), "{typo}");
    }

    #[test]
    fn kind_tags_are_the_detection_json_spelling() {
        for kind in [
            Kind::Packer,
            Kind::Compiler,
            Kind::Protector,
            Kind::Cryptor,
            Kind::Installer,
            Kind::Sfx,
            Kind::Joiner,
            Kind::Linker,
            Kind::Runtime,
            Kind::Unknown,
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), kind_tag(kind));
        }
    }
}
