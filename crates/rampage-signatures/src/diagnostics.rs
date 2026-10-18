use super::{
    Arch, CURRENT_SCHEME, Fingerprint, LEGACY_SCHEME, Lookup, MAX_INSTRUCTIONS, MIN_CONTENT_BYTES, MIN_DISTINCT,
    MIN_INSTRUCTIONS, MaskContext, Measure, SignatureDb, Target, fingerprint, fingerprint_scheme, function_hash, hex,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Read-only evidence from the production fingerprint and lookup, not an independent match or name proof.
#[derive(Debug, Clone, Serialize)]
pub struct MatchDiagnostics {
    pub target: Arch,
    pub instruction_big_endian: bool,
    pub thumb: bool,
    pub database_arch: Arch,
    pub scheme: u32,
    pub target_supported: bool,
    pub scheme_supported: bool,
    pub arch_matches: bool,
    pub fingerprint_status: FingerprintStatus,
    pub body_hash: Option<String>,
    pub scheme1_fallback_hash: Option<String>,
    pub gates: Option<GateDiagnostics>,
    /// Only content bytes and diversity apply here; the core has no separate instruction-count requirement.
    pub core_callee_gate: Option<GateDiagnostics>,
    pub instruction_limit: u32,
    /// The production matcher hashes a prefix at this limit; this does not assert that more input exists.
    pub instruction_cap_reached: bool,
    pub masked_key: KeyDiagnostics,
    pub exact_key: KeyDiagnostics,
    pub callee_key: Option<String>,
    pub callee_key_state: KeyDiagnostics,
    pub named_result: Option<String>,
    pub via: MatchVia,
    pub lookup_state: LookupState,
    /// Occurrences of native recorded direct branch/call targets outside the supplied whole-body range.
    pub external_target_count: usize,
    /// First 16 missing occurrences in instruction order, relative only to caller-supplied names.
    pub missing_callee_targets: Vec<String>,
    pub missing_callee_targets_omitted: usize,
    /// First 16 known external occurrences; supplied labels are untrusted inputs, not verified identities.
    pub known_callee_inputs: Vec<CalleeNameInput>,
    pub known_omitted: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CalleeNameInput {
    pub source: CalleeNameSource,
    pub address: String,
    /// At most 256 Unicode scalar values, without normalizing or modifying the supplied name.
    pub name_preview: String,
    pub name_bytes: usize,
    pub name_sha256: String,
    pub name_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CalleeNameSource {
    CallerSupplied,
}

impl CalleeNameInput {
    fn new(address: u64, name: &str) -> Self {
        let mut chars = name.chars();
        let name_preview = chars.by_ref().take(256).collect();
        Self {
            source: CalleeNameSource::CallerSupplied,
            address: format!("{address:#x}"),
            name_preview,
            name_bytes: name.len(),
            name_sha256: hex(&Sha256::digest(name.as_bytes())),
            name_truncated: chars.next().is_some(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintStatus {
    UnsupportedScheme,
    UnsupportedTarget,
    /// Empty, truncated or invalid input yielded no instructions under the native fingerprint rules.
    NoDecodedInstructions,
    LowContent,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupState {
    Named,
    AwaitsCallees,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchVia {
    Masked,
    Exact,
    Callees,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct KeyDiagnostics {
    pub present: bool,
    /// Actual per-key database tombstone, never inferred from an absent entry.
    pub ambiguous: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateDiagnostics {
    pub instruction_count: u32,
    pub minimum_instructions: u32,
    pub instructions_pass: bool,
    pub content_bytes: usize,
    pub minimum_content_bytes: usize,
    pub content_bytes_pass: bool,
    /// Saturates at `minimum_distinct_encodings`, just as the production measure does.
    pub distinct_encodings_capped: usize,
    pub minimum_distinct_encodings: usize,
    pub distinct_encodings_pass: bool,
    pub has_content: bool,
    pub discriminating: bool,
}

impl From<&Measure> for GateDiagnostics {
    fn from(measure: &Measure) -> Self {
        Self {
            instruction_count: measure.instructions,
            minimum_instructions: MIN_INSTRUCTIONS,
            instructions_pass: measure.instructions >= MIN_INSTRUCTIONS,
            content_bytes: measure.content_bytes,
            minimum_content_bytes: MIN_CONTENT_BYTES,
            content_bytes_pass: measure.content_bytes >= MIN_CONTENT_BYTES,
            distinct_encodings_capped: measure.distinct.len(),
            minimum_distinct_encodings: MIN_DISTINCT,
            distinct_encodings_pass: measure.distinct.len() >= MIN_DISTINCT,
            has_content: measure.has_content(),
            discriminating: measure.discriminating(),
        }
    }
}

fn key_state(key: Option<&String>, entries: &BTreeMap<String, String>, ambiguous: &BTreeSet<String>) -> KeyDiagnostics {
    KeyDiagnostics {
        present: key.is_some_and(|key| entries.contains_key(key)),
        ambiguous: key.is_some_and(|key| ambiguous.contains(key)),
    }
}

impl SignatureDb {
    /// Explains the existing exact matcher without changing this database or trusting supplied callee names.
    /// `callees` supplies caller-owned labels; their provenance is unknown here. Missing names are not a claim
    /// about program discovery, and previews never replace full labels in the production callee key.
    pub fn explain_in(
        &self,
        target: &Target,
        image: &MaskContext,
        bytes: &[u8],
        address: u64,
        callees: &BTreeMap<u64, String>,
    ) -> MatchDiagnostics {
        let name = |at: u64| callees.get(&at).map(String::as_str);
        let print = fingerprint_scheme(self.scheme, target, image, bytes, address);
        let scheme_supported = matches!(self.scheme, LEGACY_SCHEME | CURRENT_SCHEME);
        let target_supported = fingerprint(target, &[], address, None).is_some();
        let gates = print.as_ref().map(|print| GateDiagnostics::from(&print.measure));
        let core_callee_gate = print.as_ref().map(|print| GateDiagnostics::from(&print.callee_core()));
        let body = address..address.saturating_add(bytes.len() as u64);
        let callee_key = print.as_ref().and_then(|print| print.callee_key(body.clone(), name)).map(|key| hex(&key));
        let mut external_target_count = 0;
        let mut missing_callee_targets = Vec::new();
        let mut missing_callee_targets_omitted = 0;
        let mut known_callee_inputs = Vec::new();
        let mut known_omitted = 0;
        if let Some(print) = &print {
            for &at in print.branch_targets.iter().filter(|at| !body.contains(at)) {
                external_target_count += 1;
                if let Some(name) = callees.get(&at) {
                    if known_callee_inputs.len() < 16 {
                        known_callee_inputs.push(CalleeNameInput::new(at, name));
                    } else {
                        known_omitted += 1;
                    }
                } else if missing_callee_targets.len() < 16 {
                    missing_callee_targets.push(format!("{at:#x}"));
                } else {
                    missing_callee_targets_omitted += 1;
                }
            }
        }
        let instruction_cap_reached = print.as_ref().is_some_and(Fingerprint::full);
        let body_hash = print.and_then(Fingerprint::finish).map(|hash| hex(&hash));
        let scheme1_fallback_hash = function_hash(target, bytes, address).map(|hash| hex(&hash));
        let fingerprint_status = if !scheme_supported {
            FingerprintStatus::UnsupportedScheme
        } else if !target_supported {
            FingerprintStatus::UnsupportedTarget
        } else if gates.as_ref().is_some_and(|gate| gate.instruction_count == 0) {
            FingerprintStatus::NoDecodedInstructions
        } else if body_hash.is_none() {
            FingerprintStatus::LowContent
        } else {
            FingerprintStatus::Ready
        };
        let masked_key = key_state(body_hash.as_ref(), &self.entries, &self.ambiguous);
        let exact_key = key_state(scheme1_fallback_hash.as_ref(), &self.exact, &self.ambiguous_exact);
        let callee_key_state = key_state(callee_key.as_ref(), &self.calls, &self.ambiguous_calls);
        let (named_result, lookup_state, via) = match self.lookup(target, image, bytes, address, name) {
            Lookup::Named(name) => {
                let agrees = |key: Option<&String>, entries: &BTreeMap<String, String>| {
                    key.and_then(|key| entries.get(key)).is_some_and(|found| found == name)
                };
                let via = if agrees(body_hash.as_ref(), &self.entries) {
                    MatchVia::Masked
                } else if agrees(scheme1_fallback_hash.as_ref(), &self.exact) {
                    MatchVia::Exact
                } else if agrees(callee_key.as_ref(), &self.calls) {
                    MatchVia::Callees
                } else {
                    MatchVia::Unknown
                };
                (Some(name.to_owned()), LookupState::Named, via)
            }
            Lookup::AwaitsCallees => (None, LookupState::AwaitsCallees, MatchVia::Unknown),
            Lookup::Unknown => (None, LookupState::Unknown, MatchVia::Unknown),
        };
        MatchDiagnostics {
            target: target.arch,
            instruction_big_endian: target.big_endian,
            thumb: target.is_thumb(address),
            database_arch: self.arch,
            scheme: self.scheme,
            target_supported,
            scheme_supported,
            arch_matches: self.arch == target.arch,
            fingerprint_status,
            body_hash,
            scheme1_fallback_hash,
            gates,
            core_callee_gate,
            instruction_limit: MAX_INSTRUCTIONS,
            instruction_cap_reached,
            masked_key,
            exact_key,
            callee_key,
            callee_key_state,
            named_result,
            via,
            lookup_state,
            external_target_count,
            missing_callee_targets,
            missing_callee_targets_omitted,
            known_callee_inputs,
            known_omitted,
        }
    }
}
