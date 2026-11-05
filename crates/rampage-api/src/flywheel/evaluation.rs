//! One split evaluated under a candidate's layers against a reference (the baseline or the current promoted
//! state): per-slice metrics, their deltas, the cases that changed, and the gate rules applied to them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::FlywheelError;
use super::corpus::Split;
use super::engine::{Counts, Engine, Layer, Outcome, SliceMetrics, round, slice_counts};

/// One slice's change from the reference to the candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SliceDelta {
    pub tp: i64,
    pub fp: i64,
    #[serde(rename = "fn")]
    pub fn_: i64,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

impl SliceDelta {
    fn between(before: &Counts, after: &Counts) -> SliceDelta {
        let difference = |after: u64, before: u64| after as i64 - before as i64;
        SliceDelta {
            tp: difference(after.tp(), before.tp()),
            fp: difference(after.fp(), before.fp()),
            fn_: difference(after.fn_(), before.fn_()),
            precision: round(after.precision() - before.precision()),
            recall: round(after.recall() - before.recall()),
            f1: round(after.f1() - before.f1()),
        }
    }
}

/// An address whose outcome or name changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangedCase {
    pub binary: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_outcome: Option<Outcome>,
    /// `fixed` (now correct, or a wrong/spurious name gone), `broken` (was correct, or a new wrong/spurious
    /// name) or `changed`.
    pub effect: String,
}

/// A split evaluated: the candidate's and the reference's counts per slice, their deltas, and the changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SplitEvaluation {
    pub split: Split,
    pub binaries: usize,
    /// Binaries identified again; the rest kept their cached answers because no layer could change them.
    pub reidentified: usize,
    pub elapsed_ms: u64,
    pub reference: BTreeMap<String, Counts>,
    pub candidate: BTreeMap<String, Counts>,
    pub fixed: usize,
    pub broken: usize,
    /// Every changed case, unless the split is held out: then none, ever.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cases: Vec<ChangedCase>,
}

impl SplitEvaluation {
    /// The candidate's metrics per slice.
    pub fn metrics(&self) -> BTreeMap<String, SliceMetrics> {
        self.candidate.iter().map(|(slice, counts)| (slice.clone(), SliceMetrics::from(*counts))).collect()
    }

    /// The reference's metrics per slice.
    pub fn reference_metrics(&self) -> BTreeMap<String, SliceMetrics> {
        self.reference.iter().map(|(slice, counts)| (slice.clone(), SliceMetrics::from(*counts))).collect()
    }

    pub fn deltas(&self) -> BTreeMap<String, SliceDelta> {
        self.candidate
            .iter()
            .map(|(slice, after)| {
                let before = self.reference.get(slice).copied().unwrap_or_default();
                (slice.clone(), SliceDelta::between(&before, after))
            })
            .collect()
    }

    /// Each slice's F1 change, unrounded, for the gate.
    fn f1_changes(&self) -> BTreeMap<&str, f64> {
        self.candidate
            .iter()
            .map(|(slice, after)| {
                let before = self.reference.get(slice).copied().unwrap_or_default();
                (slice.as_str(), after.f1() - before.f1())
            })
            .collect()
    }

    fn overall(&self) -> (Counts, Counts) {
        (self.reference.get("all").copied().unwrap_or_default(), self.candidate.get("all").copied().unwrap_or_default())
    }
}

/// Evaluates `split` under `layers` against `reference` layers. Held-out evaluations never keep cases.
pub fn evaluate_split(
    engine: &Engine,
    split: Split,
    layers: &[Layer],
    reference: &[Layer],
) -> Result<SplitEvaluation, FlywheelError> {
    let indices = engine.corpus.indices(split);
    let before = engine.propose(&indices, reference)?;
    let after = engine.propose(&indices, layers)?;
    let mut reference_outcomes = BTreeMap::new();
    let mut candidate_outcomes = BTreeMap::new();
    let (mut fixed, mut broken) = (0, 0);
    let mut cases = Vec::new();
    for &index in &indices {
        let loaded = engine.get(index)?;
        let empty = BTreeMap::new();
        let before_names = before.names.get(&index).unwrap_or(&empty);
        let after_names = after.names.get(&index).unwrap_or(&empty);
        let before_outcomes = loaded.outcomes(before_names);
        let after_outcomes = loaded.outcomes(after_names);
        let addresses: std::collections::BTreeSet<u64> =
            before_outcomes.keys().chain(after_outcomes.keys()).copied().collect();
        for address in addresses {
            let (was, now) = (before_outcomes.get(&address).copied(), after_outcomes.get(&address).copied());
            let (old, new) = (before_names.get(&address), after_names.get(&address));
            if was == now && old == new {
                continue;
            }
            let effect = effect(was, now);
            match effect {
                "fixed" => fixed += 1,
                "broken" => broken += 1,
                _ => {}
            }
            if split != Split::Heldout {
                cases.push(ChangedCase {
                    binary: engine.binary(index).id.clone(),
                    address: format!("{address:#x}"),
                    truth: loaded.truth.get(&address).map(|truth| truth.name.clone()),
                    before: old.cloned(),
                    after: new.cloned(),
                    before_outcome: was,
                    after_outcome: now,
                    effect: effect.to_owned(),
                });
            }
        }
        reference_outcomes.insert(index, before_outcomes);
        candidate_outcomes.insert(index, after_outcomes);
    }
    Ok(SplitEvaluation {
        split,
        binaries: indices.len(),
        reidentified: before.reidentified + after.reidentified,
        elapsed_ms: before.elapsed_ms + after.elapsed_ms,
        reference: slice_counts(engine, &reference_outcomes),
        candidate: slice_counts(engine, &candidate_outcomes),
        fixed,
        broken,
        cases,
    })
}

fn effect(was: Option<Outcome>, now: Option<Outcome>) -> &'static str {
    let error = |outcome: Option<Outcome>| matches!(outcome, Some(Outcome::Wrong | Outcome::Spurious));
    if now == Some(Outcome::Correct) && was != Some(Outcome::Correct) || error(was) && !error(now) {
        "fixed"
    } else if was == Some(Outcome::Correct) && now != Some(Outcome::Correct) || error(now) && !error(was) {
        "broken"
    } else {
        "changed"
    }
}

/// The promotion gate. Every rule is checked on its split's counts, unrounded; the defaults are conservative:
/// a held-out F1 gain of at least 0.001 overall, no slice losing any F1, and not one false positive more.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GateConfig {
    /// The held-out split's overall F1 must rise by at least this much (and by more than nothing).
    pub min_f1_gain: f64,
    /// No slice, on either split, may lose more F1 than this.
    pub max_slice_f1_drop: f64,
    /// The held-out split's false positives (wrong and spurious names) may rise by at most this many.
    pub max_fp_increase: u64,
    /// The fast slice's false positives may rise by at most this many.
    pub max_fast_fp_increase: u64,
    /// Held-out evaluations one server may run (cached results excepted), bounding how much a proposer can
    /// learn about the held-out split from its metrics.
    pub max_heldout_evaluations: usize,
}

impl Default for GateConfig {
    fn default() -> GateConfig {
        GateConfig {
            min_f1_gain: 0.001,
            max_slice_f1_drop: 0.0,
            max_fp_increase: 0,
            max_fast_fp_increase: 0,
            max_heldout_evaluations: 12,
        }
    }
}

impl GateConfig {
    /// Reads a TOML gate file; unknown keys are refused and missing ones keep their defaults.
    pub fn from_toml(text: &str) -> Result<GateConfig, FlywheelError> {
        let config: GateConfig =
            toml::from_str(text).map_err(|error| FlywheelError::Invalid(format!("gate: {error}")))?;
        let negative =
            [config.min_f1_gain, config.max_slice_f1_drop].iter().any(|value| !value.is_finite() || *value < 0.0);
        if negative {
            return Err(FlywheelError::Invalid("gate: F1 thresholds must be finite and not negative".to_owned()));
        }
        Ok(config)
    }

    pub fn fingerprint(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The fast gate: rejects a candidate that adds false positives or costs any slice F1 on the fast slice.
    pub fn fast(&self, evaluation: &SplitEvaluation) -> GateResult {
        let (before, after) = evaluation.overall();
        let fp_rise = after.fp() as i64 - before.fp() as i64;
        let mut checks = vec![GateCheck::new(
            "fast_fp_increase",
            fp_rise <= self.max_fast_fp_increase as i64,
            format!("false positives {fp_rise:+} on the fast slice (at most +{})", self.max_fast_fp_increase),
        )];
        checks.push(self.slice_check("fast_slice_regression", evaluation));
        GateResult::new("fast", checks, self.failing_slices(evaluation))
    }

    /// The held-out gate: the overall F1 gain, no slice regression, and the false-positive bound.
    pub fn heldout(&self, evaluation: &SplitEvaluation) -> GateResult {
        let (before, after) = evaluation.overall();
        let gain = after.f1() - before.f1();
        let fp_rise = after.fp() as i64 - before.fp() as i64;
        let checks = vec![
            GateCheck::new(
                "heldout_f1_gain",
                gain > 0.0 && gain + 1e-12 >= self.min_f1_gain,
                format!("overall F1 {:+.6} (at least +{})", gain, self.min_f1_gain),
            ),
            GateCheck::new(
                "heldout_fp_increase",
                fp_rise <= self.max_fp_increase as i64,
                format!("false positives {fp_rise:+} (at most +{})", self.max_fp_increase),
            ),
            self.slice_check("heldout_slice_regression", evaluation),
        ];
        GateResult::new("heldout", checks, self.failing_slices(evaluation))
    }

    fn failing_slices(&self, evaluation: &SplitEvaluation) -> Vec<String> {
        let changes = evaluation.f1_changes();
        changes
            .into_iter()
            .filter(|(_, change)| *change + 1e-12 < -self.max_slice_f1_drop)
            .map(|(slice, _)| slice.to_owned())
            .collect()
    }

    fn slice_check(&self, rule: &'static str, evaluation: &SplitEvaluation) -> GateCheck {
        let failing = self.failing_slices(evaluation);
        let detail = if failing.is_empty() {
            format!("no slice loses more than {} F1", self.max_slice_f1_drop)
        } else {
            format!("{} slices lose more than {} F1", failing.len(), self.max_slice_f1_drop)
        };
        GateCheck::new(rule, failing.is_empty(), detail)
    }
}

/// One gate rule's verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateCheck {
    pub rule: String,
    pub passed: bool,
    pub detail: String,
}

impl GateCheck {
    fn new(rule: &str, passed: bool, detail: String) -> GateCheck {
        GateCheck { rule: rule.to_owned(), passed, detail }
    }
}

/// A gate stage's verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateResult {
    pub stage: String,
    pub passed: bool,
    pub checks: Vec<GateCheck>,
    /// Slices that lost more F1 than allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing_slices: Vec<String>,
}

impl GateResult {
    fn new(stage: &str, checks: Vec<GateCheck>, failing_slices: Vec<String>) -> GateResult {
        GateResult { stage: stage.to_owned(), passed: checks.iter().all(|check| check.passed), checks, failing_slices }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluation(before: Counts, after: Counts, slice_before: Counts, slice_after: Counts) -> SplitEvaluation {
        SplitEvaluation {
            split: Split::Heldout,
            binaries: 1,
            reidentified: 1,
            elapsed_ms: 0,
            reference: BTreeMap::from([("all".to_owned(), before), ("arch:x86_64".to_owned(), slice_before)]),
            candidate: BTreeMap::from([("all".to_owned(), after), ("arch:x86_64".to_owned(), slice_after)]),
            fixed: 0,
            broken: 0,
            cases: vec![],
        }
    }

    fn counts(correct: u64, wrong: u64, missed: u64, spurious: u64) -> Counts {
        Counts { correct, wrong, missed, spurious }
    }

    #[test]
    fn metrics_count_a_wrong_name_as_a_false_positive_and_a_miss() {
        let counts = counts(8, 1, 1, 0);
        assert_eq!((counts.tp(), counts.fp(), counts.fn_()), (8, 1, 2));
        assert!((counts.precision() - 8.0 / 9.0).abs() < 1e-12);
        assert!((counts.recall() - 0.8).abs() < 1e-12);
        assert!((counts.f1() - 16.0 / 19.0).abs() < 1e-12);
    }

    #[test]
    fn the_heldout_gate_needs_the_minimum_gain_and_rejects_false_positives_and_slice_regressions() {
        let gate = GateConfig::default();
        let base = counts(500, 0, 500, 0);
        // Ten more correct names out of a thousand: F1 rises by about 0.0066.
        let better = counts(510, 0, 490, 0);
        assert!(gate.heldout(&evaluation(base, better, base, better)).passed);

        // One more correct name is below the default minimum gain.
        let marginal = counts(501, 0, 499, 0);
        let result = gate.heldout(&evaluation(base, marginal, base, marginal));
        assert!(!result.passed);
        assert!(!result.checks.iter().find(|check| check.rule == "heldout_f1_gain").unwrap().passed);
        // With a lower minimum it passes, and with none it still needs a strict gain.
        let lenient = GateConfig { min_f1_gain: 0.0, ..GateConfig::default() };
        assert!(lenient.heldout(&evaluation(base, marginal, base, marginal)).passed);
        assert!(!lenient.heldout(&evaluation(base, base, base, base)).passed);

        // A gain bought with one false positive fails the default.
        let noisy = counts(510, 0, 490, 1);
        let result = gate.heldout(&evaluation(base, noisy, base, noisy));
        assert!(!result.checks.iter().find(|check| check.rule == "heldout_fp_increase").unwrap().passed);

        // An overall gain with one slice losing F1 fails the slice rule and names the slice.
        let slice_worse = counts(400, 1, 100, 0);
        let result = gate.heldout(&evaluation(base, better, counts(400, 0, 100, 0), slice_worse));
        assert!(!result.passed);
        assert_eq!(result.failing_slices, ["arch:x86_64"]);
    }

    #[test]
    fn the_fast_gate_rejects_new_false_positives_but_passes_no_change() {
        let gate = GateConfig::default();
        let base = counts(100, 0, 50, 0);
        assert!(gate.fast(&evaluation(base, base, base, base)).passed);
        let spurious = counts(100, 0, 50, 1);
        assert!(!gate.fast(&evaluation(base, spurious, base, spurious)).passed);
    }

    #[test]
    fn gate_files_override_defaults_and_refuse_unknown_keys() {
        let config = GateConfig::from_toml("min_f1_gain = 0.002\n").unwrap();
        assert_eq!(config.min_f1_gain, 0.002);
        assert_eq!(config.max_fp_increase, 0);
        assert!(GateConfig::from_toml("min_gain = 1\n").is_err());
        assert!(GateConfig::from_toml("min_f1_gain = -1\n").is_err());
    }
}
