//! One split evaluated under a candidate's layers against a reference (the baseline or the current promoted
//! state): per-slice metrics, their deltas, the cases that changed, and the gate rules applied to them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::FlywheelError;
use super::corpus::Split;
use super::engine::{Counts, Engine, Layer, Outcome, Proposals, SliceMetrics, gated_slice, round, slice_counts};

/// The held-out slice of target-library functions whose masked body training does not hold: a gain here is
/// generalisation to changed code, not recognition of unchanged code.
pub const NOVEL_SLICE: &str = "novelty:novel";
/// The held-out slice of target-library functions whose masked body training also holds.
pub const RECOGNISED_SLICE: &str = "novelty:recognised";

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

    /// Each gated slice's F1 change, unrounded, for the gate.
    fn f1_changes(&self) -> BTreeMap<&str, f64> {
        self.candidate
            .iter()
            .filter(|(slice, _)| gated_slice(slice))
            .map(|(slice, after)| {
                let before = self.reference.get(slice).copied().unwrap_or_default();
                (slice.as_str(), after.f1() - before.f1())
            })
            .collect()
    }

    /// The gated scope's counts before and after: target-library functions, plus every false name.
    pub fn overall(&self) -> (Counts, Counts) {
        self.slice("all")
    }

    /// One slice's counts before and after.
    pub fn slice(&self, slice: &str) -> (Counts, Counts) {
        (self.reference.get(slice).copied().unwrap_or_default(), self.candidate.get(slice).copied().unwrap_or_default())
    }
}

/// Evaluates `split` under `layers` against `reference` layers. Held-out and final evaluations never keep cases.
pub fn evaluate_split(
    engine: &Engine,
    split: Split,
    layers: &[Layer],
    reference: &[Layer],
) -> Result<SplitEvaluation, FlywheelError> {
    let indices = engine.corpus.indices(split);
    let before = engine.propose(&indices, reference)?;
    let after = engine.propose(&indices, layers)?;
    compare(engine, split, &before, &after)
}

/// The held-out (development) split under `layers` against `reference`, keeping its changed cases: for the
/// operator designing arms and rules, never for a proposer. The improve server does not call it; the final split
/// has no such view.
pub fn evaluate_dev_with_cases(
    engine: &Engine,
    layers: &[Layer],
    reference: &[Layer],
) -> Result<SplitEvaluation, FlywheelError> {
    let indices = engine.corpus.indices(Split::Heldout);
    let before = engine.propose(&indices, reference)?;
    let after = engine.propose(&indices, layers)?;
    compare_keeping(engine, Split::Heldout, &before, &after, true)
}

/// Scores `split` from the names a reference (`before`) and a candidate (`after`) gave its binaries. Held-out and
/// final evaluations never keep cases.
pub fn compare(
    engine: &Engine,
    split: Split,
    before: &Proposals,
    after: &Proposals,
) -> Result<SplitEvaluation, FlywheelError> {
    compare_keeping(engine, split, before, after, !matches!(split, Split::Heldout | Split::Final))
}

fn compare_keeping(
    engine: &Engine,
    split: Split,
    before: &Proposals,
    after: &Proposals,
    keep_cases: bool,
) -> Result<SplitEvaluation, FlywheelError> {
    let indices = engine.corpus.indices(split);
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
            if keep_cases {
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
        reference: slice_counts(engine, &reference_outcomes)?,
        candidate: slice_counts(engine, &candidate_outcomes)?,
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

/// The promotion gate. Every rule is checked on its split's gated counts (target-library functions, plus every
/// false name), unrounded. The defaults are conservative: a held-out F1 gain of at least 0.001, at most one false
/// positive more on the held-out split for every 100 correct names it gains (none for a smaller gain), not one
/// more on the full training split or the negatives, no gated slice losing any F1, and rows of at least 32 bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GateConfig {
    /// The held-out split's overall F1 must rise by at least this much (and by more than nothing).
    pub min_f1_gain: f64,
    /// No gated slice, on any split, may lose more F1 than this.
    pub max_slice_f1_drop: f64,
    /// The held-out split's false positives (wrong and spurious names) may rise by at most this many, plus the
    /// allowance `tp_per_fp` earns.
    pub max_fp_increase: u64,
    /// One more held-out false positive is allowed for every this many correct names the held-out split gains; 0
    /// allows none. A collision training cannot reveal (two names for one body, the second only in the held-out
    /// version) would otherwise block any candidate, however much it gains.
    pub tp_per_fp: u64,
    /// The full training split's false positives may rise by at most this many.
    pub max_train_fp_increase: u64,
    /// Names the candidate may add on the negative binaries, where every target name is false.
    pub max_negative_matches: u64,
    /// The shortest pattern a row may have, in bytes: short bodies (accessors, thunks) collide across code that
    /// merely looks alike.
    pub min_pattern_bytes: usize,
    /// Held-out evaluations per corpus (across every server and run, cached results excepted), bounding how much
    /// a proposer can learn about the held-out split from its metrics.
    pub max_heldout_evaluations: usize,
    /// Whether the held-out gate also needs an F1 gain on the novel held-out functions (bodies training does not
    /// hold). Unset, it follows the baseline: required against the deterministic arm, which already names the
    /// functions training holds, and not against the bundled databases alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_novel_gain: Option<bool>,
    /// The novel slice's F1 must rise by at least this much (and by more than nothing) when a novel gain is
    /// required.
    pub min_novel_f1_gain: f64,
}

impl Default for GateConfig {
    fn default() -> GateConfig {
        GateConfig {
            min_f1_gain: 0.001,
            max_slice_f1_drop: 0.0,
            max_fp_increase: 0,
            tp_per_fp: 100,
            max_train_fp_increase: 0,
            max_negative_matches: 0,
            min_pattern_bytes: 32,
            max_heldout_evaluations: 20,
            require_novel_gain: None,
            min_novel_f1_gain: 0.001,
        }
    }
}

impl GateConfig {
    /// Reads a TOML gate file; unknown keys are refused and missing ones keep their defaults.
    pub fn from_toml(text: &str) -> Result<GateConfig, FlywheelError> {
        let config: GateConfig =
            toml::from_str(text).map_err(|error| FlywheelError::Invalid(format!("gate: {error}")))?;
        let negative = [config.min_f1_gain, config.max_slice_f1_drop, config.min_novel_f1_gain]
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0);
        if negative {
            return Err(FlywheelError::Invalid("gate: F1 thresholds must be finite and not negative".to_owned()));
        }
        Ok(config)
    }

    pub fn fingerprint(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The fast gate, on training data and negatives only: no new false positives on the full training split,
    /// no new name on the negatives, and no gated slice losing F1 on the fast slice or the training split.
    pub fn fast(&self, fast: &SplitEvaluation, train: &SplitEvaluation, negative: &SplitEvaluation) -> GateResult {
        let rise = |evaluation: &SplitEvaluation| {
            let (before, after) = evaluation.overall();
            after.fp() as i64 - before.fp() as i64
        };
        let (train_rise, negative_rise) = (rise(train), rise(negative));
        let mut failing = self.failing_slices(fast);
        failing.extend(self.failing_slices(train).into_iter().map(|slice| format!("train {slice}")));
        let checks = vec![
            GateCheck::new(
                "train_fp_increase",
                train_rise <= self.max_train_fp_increase as i64,
                format!(
                    "false positives {train_rise:+} on the training split (at most +{})",
                    self.max_train_fp_increase
                ),
            ),
            GateCheck::new(
                "negative_matches",
                negative_rise <= self.max_negative_matches as i64,
                format!(
                    "{negative_rise:+} names on the negative binaries, where every target name is false (at most +{})",
                    self.max_negative_matches
                ),
            ),
            GateCheck::new(
                "train_slice_regression",
                failing.is_empty(),
                if failing.is_empty() {
                    format!("no gated training slice loses more than {} F1", self.max_slice_f1_drop)
                } else {
                    format!("{} gated training slices lose more than {} F1", failing.len(), self.max_slice_f1_drop)
                },
            ),
        ];
        GateResult::new("fast", checks, failing)
    }

    /// Whether a novel gain is required, given whether the baseline includes the deterministic arm.
    pub fn novel_gain_required(&self, arm_baseline: bool) -> bool {
        self.require_novel_gain.unwrap_or(arm_baseline)
    }

    /// How many more false positives the held-out split may have under `evaluation`: `max_fp_increase`, plus one
    /// for every `tp_per_fp` correct names gained.
    pub fn heldout_fp_allowance(&self, evaluation: &SplitEvaluation) -> u64 {
        let (before, after) = evaluation.overall();
        let gained = after.tp().saturating_sub(before.tp());
        let earned = gained.checked_div(self.tp_per_fp).unwrap_or(0);
        self.max_fp_increase.saturating_add(earned)
    }

    /// The held-out gate: the overall F1 gain, false positives within the allowance
    /// ([`GateConfig::heldout_fp_allowance`]), no gated slice regression and, when `require_novel`, an F1 gain on
    /// the novel held-out functions.
    pub fn heldout(&self, evaluation: &SplitEvaluation, require_novel: bool) -> GateResult {
        let (before, after) = evaluation.overall();
        let gain = after.f1() - before.f1();
        let fp_rise = after.fp() as i64 - before.fp() as i64;
        let allowance = self.heldout_fp_allowance(evaluation);
        let failing = self.failing_slices(evaluation);
        let mut checks = vec![
            GateCheck::new(
                "heldout_f1_gain",
                gain > 0.0 && gain + 1e-12 >= self.min_f1_gain,
                format!("overall F1 {:+.6} (at least +{})", gain, self.min_f1_gain),
            ),
            GateCheck::new(
                "heldout_fp_increase",
                fp_rise <= allowance as i64,
                format!(
                    "false positives {fp_rise:+} (at most +{allowance}: +{} and one per {} correct names gained)",
                    self.max_fp_increase, self.tp_per_fp
                ),
            ),
            // Which slices regress would tell a proposer where held-out code lies: the verdict alone is given.
            GateCheck::new(
                "heldout_slice_regression",
                failing.is_empty(),
                format!("no gated slice may lose more than {} F1", self.max_slice_f1_drop),
            ),
        ];
        if require_novel {
            let (before, after) = evaluation.slice(NOVEL_SLICE);
            let novel = after.f1() - before.f1();
            checks.push(GateCheck::new(
                "heldout_novel_f1_gain",
                novel > 0.0 && novel + 1e-12 >= self.min_novel_f1_gain,
                format!("novel-body F1 {novel:+.6} (at least +{})", self.min_novel_f1_gain),
            ));
        }
        GateResult::new("heldout", checks, failing)
    }

    fn failing_slices(&self, evaluation: &SplitEvaluation) -> Vec<String> {
        let changes = evaluation.f1_changes();
        changes
            .into_iter()
            .filter(|(_, change)| *change + 1e-12 < -self.max_slice_f1_drop)
            .map(|(slice, _)| slice.to_owned())
            .collect()
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

    /// Adds a rule's verdict; the stage passes only if every rule does.
    pub fn add(&mut self, check: GateCheck) {
        self.passed &= check.passed;
        self.checks.push(check);
    }
}

impl GateConfig {
    /// The false-positive rules on the state a promotion deploys: the bundled databases, the promoted rows and the
    /// candidate, without the deterministic arm. Gated against the arm, a candidate row whose pattern also matches a
    /// body an arm row names under another name makes that body ambiguous (a lost name) rather than wrongly named;
    /// the arm is never deployed, so the promoted row alone would name it wrongly. `rises` are (rule, false
    /// positives added, at most) for each split measured.
    pub fn deployed(&self, rises: &[(&str, i64, u64)]) -> Vec<GateCheck> {
        rises
            .iter()
            .map(|&(rule, rise, most)| {
                GateCheck::new(
                    rule,
                    rise <= most as i64,
                    format!("false positives {rise:+} without the arm, as the promotion deploys (at most +{most})"),
                )
            })
            .collect()
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
        assert!(gate.heldout(&evaluation(base, better, base, better), false).passed);

        // One more correct name is below the default minimum gain.
        let marginal = counts(501, 0, 499, 0);
        let result = gate.heldout(&evaluation(base, marginal, base, marginal), false);
        assert!(!result.passed);
        assert!(!result.checks.iter().find(|check| check.rule == "heldout_f1_gain").unwrap().passed);
        // With a lower minimum it passes, and with none it still needs a strict gain.
        let lenient = GateConfig { min_f1_gain: 0.0, ..GateConfig::default() };
        assert!(lenient.heldout(&evaluation(base, marginal, base, marginal), false).passed);
        assert!(!lenient.heldout(&evaluation(base, base, base, base), false).passed);

        // A gain bought with one false positive fails the default.
        let noisy = counts(510, 0, 490, 1);
        let result = gate.heldout(&evaluation(base, noisy, base, noisy), false);
        assert!(!result.checks.iter().find(|check| check.rule == "heldout_fp_increase").unwrap().passed);

        // An overall gain with one slice losing F1 fails the slice rule and names the slice.
        let slice_worse = counts(400, 1, 100, 0);
        let result = gate.heldout(&evaluation(base, better, counts(400, 0, 100, 0), slice_worse), false);
        assert!(!result.passed);
        assert_eq!(result.failing_slices, ["arch:x86_64"]);
    }

    #[test]
    fn large_held_out_gains_earn_a_false_positive_allowance() {
        let gate = GateConfig::default();
        let base = counts(500, 0, 9500, 0);
        let fp_check =
            |result: &GateResult| result.checks.iter().find(|c| c.rule == "heldout_fp_increase").unwrap().passed;
        // 250 more correct names earn two false positives, not three.
        let two = counts(750, 0, 9250, 2);
        let three = counts(750, 0, 9250, 3);
        assert_eq!(gate.heldout_fp_allowance(&evaluation(base, two, base, two)), 2);
        assert!(fp_check(&gate.heldout(&evaluation(base, two, base, two), false)));
        assert!(!fp_check(&gate.heldout(&evaluation(base, three, base, three), false)));
        // A wrong name costs a correct one: the gain is counted net.
        let wrong = counts(599, 1, 9400, 0);
        assert_eq!(gate.heldout_fp_allowance(&evaluation(base, wrong, base, wrong)), 0);
        // Without the ratio there is no allowance.
        let strict = GateConfig { tp_per_fp: 0, ..GateConfig::default() };
        assert!(!fp_check(&strict.heldout(&evaluation(base, two, base, two), false)));
    }

    #[test]
    fn the_fast_gate_rejects_new_false_positives_on_training_and_any_name_on_negatives() {
        let gate = GateConfig::default();
        let base = counts(100, 0, 50, 0);
        let same = evaluation(base, base, base, base);
        assert!(gate.fast(&same, &same, &same).passed);
        let spurious = counts(100, 0, 50, 1);
        let noisy = evaluation(base, spurious, base, spurious);
        let result = gate.fast(&same, &noisy, &same);
        assert!(!result.checks.iter().find(|check| check.rule == "train_fp_increase").unwrap().passed);
        let result = gate.fast(&same, &same, &noisy);
        assert!(!result.passed);
        assert!(!result.checks.iter().find(|check| check.rule == "negative_matches").unwrap().passed);
    }

    #[test]
    fn origin_slices_are_reported_but_never_gated() {
        let gate = GateConfig { min_f1_gain: 0.0, ..GateConfig::default() };
        let base = counts(500, 0, 500, 0);
        let better = counts(510, 0, 490, 0);
        let mut evaluation = evaluation(base, better, base, better);
        evaluation.reference.insert("origin:runtime".to_owned(), counts(100, 0, 0, 0));
        evaluation.candidate.insert("origin:runtime".to_owned(), counts(90, 0, 10, 0));
        assert!(gate.heldout(&evaluation, false).passed, "a runtime slice losing F1 is not a gated regression");
    }

    #[test]
    fn a_required_novel_gain_rejects_gains_from_recognised_bodies_alone() {
        let gate = GateConfig::default();
        let base = counts(500, 0, 500, 0);
        let better = counts(510, 0, 490, 0);
        let mut recognised_only = evaluation(base, better, base, better);
        recognised_only.reference.insert(RECOGNISED_SLICE.to_owned(), counts(400, 0, 100, 0));
        recognised_only.candidate.insert(RECOGNISED_SLICE.to_owned(), counts(410, 0, 90, 0));
        recognised_only.reference.insert(NOVEL_SLICE.to_owned(), counts(100, 0, 400, 0));
        recognised_only.candidate.insert(NOVEL_SLICE.to_owned(), counts(100, 0, 400, 0));
        assert!(gate.heldout(&recognised_only, false).passed, "without the rule, an overall gain passes");
        let result = gate.heldout(&recognised_only, true);
        assert!(!result.passed);
        let novel = result.checks.iter().find(|check| check.rule == "heldout_novel_f1_gain").unwrap();
        assert!(!novel.passed, "{novel:?}");

        let mut generalised = recognised_only.clone();
        generalised.candidate.insert(NOVEL_SLICE.to_owned(), counts(110, 0, 390, 0));
        assert!(gate.heldout(&generalised, true).passed);
        // Below the novel minimum, it still fails.
        let mut marginal = recognised_only.clone();
        marginal.candidate.insert(NOVEL_SLICE.to_owned(), counts(100, 0, 400, 0));
        marginal.candidate.insert(NOVEL_SLICE.to_owned(), counts(101, 0, 399, 0));
        let strict = GateConfig { min_novel_f1_gain: 0.01, ..GateConfig::default() };
        assert!(!strict.heldout(&marginal, true).passed);

        // Unset, the rule follows the baseline; a gate file can force it either way.
        assert!(gate.novel_gain_required(true) && !gate.novel_gain_required(false));
        let forced = GateConfig::from_toml("require_novel_gain = true\nmin_novel_f1_gain = 0.002\n").unwrap();
        assert!(forced.novel_gain_required(false));
        assert_eq!(forced.min_novel_f1_gain, 0.002);
        assert!(!GateConfig::from_toml("require_novel_gain = false\n").unwrap().novel_gain_required(true));
        assert!(GateConfig::from_toml("min_novel_f1_gain = -0.1\n").is_err());
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
