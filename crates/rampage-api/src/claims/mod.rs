//! `check_claim`: check stated claims about a binary mechanically and answer verified, refuted or unknown, with the
//! evidence, the method and how certain the method is.
//!
//! A claim is structured JSON, never free text. Each kind rests on existing machinery: `returns` and `computes` on
//! `evaluate_function` (and reference implementations in Rust), `calls` on the function graph and call references,
//! `references` on xrefs, `constant` on code search, `region` on recomputing checksums over image bytes and
//! `integrity_checks`, `lock` on `lock_mechanisms`, `layout` on `get_type`. A verdict is never more certain than its
//! evidence: `confidence` says what the method proves (see [`Confidence`]), a refutation carries a counterexample,
//! and what the method cannot see makes the answer unknown, with what would decide it.

// An unknown or invalid Outcome is the answer a checker gives early, not an error on a hot path: returning it by
// value keeps the checkers plain.
#![allow(clippy::result_large_err)]

mod expr;
mod facts;
mod reference;
mod run;
mod statics;

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{ApiError, Project};

/// Claims one call checks.
pub const MAX_CLAIMS: usize = 32;
pub const DEFAULT_TIMEOUT_MS: u64 = 60_000;
pub const MAX_TIMEOUT_MS: u64 = 300_000;
/// Below this much time left, a claim is not started.
const MIN_CLAIM_MS: u64 = 20;
/// Bytes of one claim's JSON.
const MAX_CLAIM_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Verified,
    Refuted,
    Unknown,
    /// The claim could not be read or names nothing in the binary: not checked.
    Invalid,
}

/// What a verdict's method establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Concrete: the function was run on the stated inputs, the bytes recomputed, or the layout read from the type
    /// source. Holds for that state of the image.
    Exact,
    /// A universal claim checked on the generated inputs listed; another input could still differ.
    Sampled,
    /// From the decoded code and its references: complete for what discovery decoded, with no unresolved indirect
    /// transfer on the paths that matter. Code that computes an address or target at run time is not seen.
    Static,
    /// From a heuristic detector (lock_mechanisms) that reported its own confidence as high.
    Heuristic,
}

/// One claim's answer.
#[derive(Debug, Clone, Serialize)]
pub struct ClaimResult {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub kind: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// The claim was stated negated (`not`): the verdict is about the negation.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub negated: bool,
    pub method: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub evidence: Value,
    /// Why the answer is unknown or invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What would decide an unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimReport {
    pub results: Vec<ClaimResult>,
    pub verified: usize,
    pub refuted: usize,
    pub unknown: usize,
    pub invalid: usize,
    pub elapsed_ms: u64,
    pub timeout_ms: u64,
}

/// A checker's answer before the batch adds the claim's index, id and timing.
#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    verdict: Verdict,
    confidence: Option<Confidence>,
    method: String,
    evidence: Value,
    reason: Option<String>,
    needs: Option<String>,
}

impl Outcome {
    fn new(verdict: Verdict, confidence: Option<Confidence>, method: impl Into<String>, evidence: Value) -> Self {
        Self { verdict, confidence, method: method.into(), evidence, reason: None, needs: None }
    }

    pub(crate) fn verified(confidence: Confidence, method: impl Into<String>, evidence: Value) -> Self {
        Self::new(Verdict::Verified, Some(confidence), method, evidence)
    }

    /// A refutation; `evidence` holds the counterexample.
    pub(crate) fn refuted(confidence: Confidence, method: impl Into<String>, evidence: Value) -> Self {
        Self::new(Verdict::Refuted, Some(confidence), method, evidence)
    }

    pub(crate) fn unknown(method: impl Into<String>, evidence: Value, reason: impl Into<String>) -> Self {
        Self { reason: Some(reason.into()), ..Self::new(Verdict::Unknown, None, method, evidence) }
    }

    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        Self { reason: Some(reason.into()), ..Self::new(Verdict::Invalid, None, "", Value::Null) }
    }

    pub(crate) fn needs(self, needs: impl Into<String>) -> Self {
        Self { needs: Some(needs.into()), ..self }
    }

    /// The outcome of the negated claim: verified and refuted swap; the evidence and its confidence stay. A
    /// sampled or heuristic verification holds no counterexample to the negation, so the negation is unknown.
    fn negated(self) -> Self {
        if self.verdict == Verdict::Verified
            && matches!(self.confidence, Some(Confidence::Sampled | Confidence::Heuristic))
        {
            let reason = "the claim held on the evidence, which is not a counterexample to its negation";
            return Self { verdict: Verdict::Unknown, confidence: None, reason: Some(reason.to_owned()), ..self }
                .needs("an input or site that breaks the claim");
        }
        let verdict = match self.verdict {
            Verdict::Verified => Verdict::Refuted,
            Verdict::Refuted => Verdict::Verified,
            other => other,
        };
        Self { verdict, ..self }
    }
}

impl From<ApiError> for Outcome {
    fn from(error: ApiError) -> Self {
        Outcome::invalid(crate::tools::error_chain(&error))
    }
}

/// The time a claim may still take.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    pub deadline: Instant,
}

impl Budget {
    pub fn remaining_ms(&self) -> u64 {
        self.deadline.saturating_duration_since(Instant::now()).as_millis() as u64
    }

    pub fn expired(&self) -> bool {
        self.remaining_ms() < MIN_CLAIM_MS
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Claim {
    Returns(run::ReturnsClaim),
    Computes(run::ComputesClaim),
    Calls(statics::CallsClaim),
    References(statics::ReferencesClaim),
    Constant(statics::ConstantClaim),
    Region(facts::RegionClaim),
    Lock(facts::LockClaim),
    Layout(facts::LayoutClaim),
}

const KINDS: &str = "returns, computes, calls, references, constant, region, lock, layout";

impl Project {
    /// Checks each claim of `claims` within `timeout_ms` in all (default [`DEFAULT_TIMEOUT_MS`]), in order. A claim
    /// that cannot be read is `invalid`; the others are still checked. Claims left when the time runs out are
    /// unknown.
    pub fn check_claims(
        self: &std::sync::Arc<Self>,
        claims: &[Value],
        timeout_ms: Option<u64>,
    ) -> Result<ClaimReport, ApiError> {
        if claims.is_empty() || claims.len() > MAX_CLAIMS {
            return Err(ApiError::Invalid(format!("claims takes 1..={MAX_CLAIMS} claims")));
        }
        let timeout_ms = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(ApiError::Invalid(format!("timeout_ms must be 1..={MAX_TIMEOUT_MS}")));
        }
        let started = Instant::now();
        let budget = Budget { deadline: started + Duration::from_millis(timeout_ms) };
        let mut results = Vec::with_capacity(claims.len());
        for (index, claim) in claims.iter().enumerate() {
            let claim_started = Instant::now();
            let (kind, id, negated, outcome) = self.check_one(claim, budget);
            results.push(ClaimResult {
                index,
                id,
                kind,
                verdict: outcome.verdict,
                confidence: outcome.confidence,
                negated,
                method: outcome.method,
                evidence: outcome.evidence,
                reason: outcome.reason,
                needs: outcome.needs,
                elapsed_ms: claim_started.elapsed().as_millis() as u64,
            });
        }
        let count = |verdict| results.iter().filter(|result| result.verdict == verdict).count();
        Ok(ClaimReport {
            verified: count(Verdict::Verified),
            refuted: count(Verdict::Refuted),
            unknown: count(Verdict::Unknown),
            invalid: count(Verdict::Invalid),
            results,
            elapsed_ms: started.elapsed().as_millis() as u64,
            timeout_ms,
        })
    }

    fn check_one(self: &std::sync::Arc<Self>, claim: &Value, budget: Budget) -> (String, Option<Value>, bool, Outcome) {
        let mut claim = claim.clone();
        let kind = claim.get("kind").and_then(Value::as_str).unwrap_or("").to_owned();
        let Some(fields) = claim.as_object_mut() else {
            return (kind, None, false, Outcome::invalid("a claim is an object with a kind"));
        };
        let id = fields.remove("id");
        let negated = match fields.remove("not") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(negated)) => negated,
            Some(_) => return (kind, id, false, Outcome::invalid("not is true or false")),
        };
        if claim.to_string().len() > MAX_CLAIM_BYTES {
            return (kind, id, negated, Outcome::invalid(format!("a claim is at most {MAX_CLAIM_BYTES} bytes")));
        }
        let parsed: Claim = match serde_json::from_value(claim) {
            Ok(parsed) => parsed,
            Err(error) => {
                let reason = if kind.is_empty() {
                    format!("a claim needs a kind: {KINDS}")
                } else {
                    format!("invalid {kind} claim: {error}")
                };
                return (kind, id, negated, Outcome::invalid(reason));
            }
        };
        if budget.expired() {
            let outcome = Outcome::unknown("", Value::Null, "the call's time budget ran out before this claim")
                .needs("check it in another call, or raise timeout_ms");
            return (kind, id, negated, outcome);
        }
        let outcome = match parsed {
            Claim::Returns(claim) => run::returns(self, &claim, budget),
            Claim::Computes(claim) => run::computes(self, &claim, budget),
            Claim::Calls(claim) => statics::calls(self, &claim, budget),
            Claim::References(claim) => statics::references(self, &claim),
            Claim::Constant(claim) => statics::constant(self, &claim),
            Claim::Region(claim) => facts::region(self, &claim, budget),
            Claim::Lock(claim) => facts::lock(self, &claim, budget),
            Claim::Layout(claim) => facts::layout(self, &claim),
        };
        let outcome = if negated { outcome.negated() } else { outcome };
        (kind, id, negated, outcome)
    }
}

/// An address argument: a number, or text the project resolves (hex, decimal or a name).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum Address {
    Number(u64),
    Text(String),
}

impl Address {
    pub fn resolve(&self, project: &Project) -> Result<u64, ApiError> {
        match self {
            Address::Number(address) => Ok(*address),
            Address::Text(text) => project.resolve(text),
        }
    }
}

/// The start of the discovered function `name` names (an address inside one is refused with its start).
pub(crate) fn function_start(project: &Project, name: &Address) -> Result<u64, Outcome> {
    let address = name.resolve(project)?;
    let address = project.thumb_code_address(address).0;
    let analysis = project.analysis()?;
    if analysis.program.function_at(address).is_some() {
        return Ok(address);
    }
    let reason = match analysis.function_containing(address) {
        Some(start) => {
            format!("{address:#x} is inside {} ({start:#x}), not a function start", project.function_name(start))
        }
        None => format!("no discovered function starts at {address:#x}"),
    };
    Err(Outcome::invalid(reason))
}

pub(crate) fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let clean: String = text.chars().filter(|character| !character.is_whitespace()).collect();
    let clean = clean.strip_prefix("0x").unwrap_or(&clean);
    if !clean.len().is_multiple_of(2) {
        return Err("hex has an odd number of digits".to_owned());
    }
    (0..clean.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&clean[index..index + 2], 16).map_err(|_| "not valid hex".to_owned()))
        .collect()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hex of at most `limit` bytes of `bytes`, with `...` when cut.
pub(crate) fn hex_prefix(bytes: &[u8], limit: usize) -> String {
    if bytes.len() <= limit { hex(bytes) } else { format!("{}...", hex(&bytes[..limit])) }
}

pub(crate) fn address(value: u64) -> Value {
    json!(format!("{value:#x}"))
}
