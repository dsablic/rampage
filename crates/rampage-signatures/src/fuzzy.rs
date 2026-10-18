//! Bounded, secondary similarity evidence. Scores are similarities, not probabilities.
//!
//! This module never edits a program or returns persistent naming operations. Exact signatures must be
//! tried first. Uncalibrated, below-threshold, colliding and insufficient-margin results are candidates only;
//! even an eligible result is a proposal and must not overwrite an analyst name.
//!
//! Analysis owns function discovery. Project its blocks and intra-function edges into [`CodeProjection`],
//! without target symbol names or producer sizes. Reference projections may use producer extents. Only
//! instruction bytes in projected blocks are decoded; gaps and trailing data are not linear-swept.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use rampage_arch::{Flow, OperandKind, Target};
use rampage_loaders::Binary;
use serde::{Deserialize, Serialize};

const SCHEMA: u32 = 1;
const MAX_INSTRUCTIONS: u32 = 4096;
const MAX_BLOCKS: usize = 512;
const MAX_CONSTANTS: usize = 128;
const MAX_CALLEES: usize = 64;
const MAX_RECORDS: usize = 100_000;
const MAX_JSON_BYTES: usize = 64 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 1024;
const MAX_EXTENT_BYTES: u64 = 1024 * 1024;
const MIN_INSTRUCTIONS: u32 = 12;
const MIN_BLOCKS: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum FuzzyError {
    #[error("invalid or unsupported fuzzy evidence: {0}")]
    Evidence(&'static str),
    #[error("fuzzy JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Block indices and edges must come from the same production CFG (including resolved switch edges).
/// `extent` is discovery's complete `address..end()`, never a target's ground-truth symbol size.
#[derive(Debug, Clone)]
pub struct CodeProjection {
    pub extent: Range<u64>,
    pub blocks: Vec<Range<u64>>,
    pub edges: Vec<(usize, usize)>,
    /// Retained Program::code_modes entries within these blocks, not inferred from target symbol names.
    pub retained_code_modes: Vec<(u64, bool)>,
    /// Retained Program::resolved_flows for this function, keyed by the actual instruction address.
    pub resolved_flows: Vec<(u64, Flow)>,
}

/// A retained production resolution may refine an indirect branch/call, never change its flow kind.
pub fn validated_production_flow(decoded: Flow, retained: Option<Flow>) -> Result<Flow, FuzzyError> {
    let Some(retained) = retained else { return Ok(decoded) };
    if decoded == retained
        || matches!((decoded, retained), (Flow::IndirectCall, Flow::Call(_)) | (Flow::IndirectJump, Flow::Jump(_)))
    {
        Ok(retained)
    } else {
        Err(FuzzyError::Evidence("retained production flow is incompatible with decoded instruction"))
    }
}

/// The only permitted sources of already-known call names. Never populate these from target debug gold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalleeProvenance {
    ExactSignatureProposal,
    Import,
    Analyst,
}

#[derive(Debug, Clone)]
pub struct KnownCallee {
    pub name: String,
    pub provenance: CalleeProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FuzzyProfile {
    pub architecture: String,
    pub instruction_big_endian: bool,
    pub data_big_endian: bool,
    pub thumb: bool,
}

impl FuzzyProfile {
    fn from_target(target: &Target, address: u64) -> Self {
        Self {
            architecture: target.arch.to_string(),
            instruction_big_endian: target.big_endian,
            data_big_endian: target.data_big_endian,
            thumb: target.is_thumb(address),
        }
    }
}

/// Address-free, name-free function descriptor. Known callee names are separate, explicitly sourced evidence.
/// Private fields guide ordinary construction through decoding. Deserialized descriptors are checked on database
/// admission and matching; those checks neither authenticate their source nor prove that decoding produced them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyFeatures {
    profile: FuzzyProfile,
    extent_bytes: u64,
    code_bytes: u64,
    instructions: u32,
    blocks: u32,
    /// Joint incoming/outgoing degree histogram, each degree saturated at three.
    degree_histogram: [u32; 16],
    /// Next, jump, conditional, call, indirect jump, indirect call, return, halt.
    flow_histogram: [u32; 8],
    constants: BTreeSet<u64>,
    known_callees: BTreeMap<String, u32>,
    callee_provenance: BTreeMap<String, CalleeProvenance>,
    unknown_direct_calls: u32,
    indirect_calls: u32,
    #[serde(default)]
    retained_flow_count: u32,
    #[serde(default)]
    retained_mode_count: u32,
}

impl FuzzyFeatures {
    pub fn profile(&self) -> &FuzzyProfile {
        &self.profile
    }

    pub fn instructions(&self) -> u32 {
        self.instructions
    }

    pub fn constants(&self) -> &BTreeSet<u64> {
        &self.constants
    }

    fn validate(&self) -> Result<(), FuzzyError> {
        if self.profile.architecture.parse::<rampage_arch::Arch>().is_err()
            || (self.profile.thumb && self.profile.architecture != "arm")
            || self.instructions < MIN_INSTRUCTIONS
            || self.instructions > MAX_INSTRUCTIONS
            || self.blocks < MIN_BLOCKS
            || self.blocks as usize > MAX_BLOCKS
            || self.code_bytes < u64::from(self.instructions)
            || self.code_bytes > self.extent_bytes
            || self.extent_bytes > MAX_EXTENT_BYTES
            || self.constants.len() > MAX_CONSTANTS
            || self.constants.iter().any(|value| *value <= 1)
            || self.known_callees.len() > MAX_CALLEES
            || self.known_callees.keys().any(|name| !valid_text(name))
            || self.known_callees.values().any(|count| *count == 0 || *count > MAX_INSTRUCTIONS)
            || self.known_callees.keys().ne(self.callee_provenance.keys())
            || self.degree_histogram.iter().map(|n| u64::from(*n)).sum::<u64>() != u64::from(self.blocks)
            || self.flow_histogram.iter().map(|n| u64::from(*n)).sum::<u64>() != u64::from(self.instructions)
            || self.unknown_direct_calls > self.flow_histogram[3]
            || self.indirect_calls != self.flow_histogram[5]
            || self.retained_flow_count > self.instructions
            || self.retained_mode_count > self.instructions
            || self.known_callees.values().map(|n| u64::from(*n)).sum::<u64>() + u64::from(self.unknown_direct_calls)
                != u64::from(self.flow_histogram[3])
        {
            return Err(FuzzyError::Evidence("descriptor bounds or counts"));
        }
        if self.constants.len() < 2 && (self.constants.is_empty() || self.known_callees.is_empty()) {
            return Err(FuzzyError::Evidence("insufficient fixed constants/known-call evidence"));
        }
        Ok(())
    }

    fn same_identity_features(&self, other: &Self) -> bool {
        self.profile == other.profile
            && self.extent_bytes == other.extent_bytes
            && self.code_bytes == other.code_bytes
            && self.instructions == other.instructions
            && self.blocks == other.blocks
            && self.degree_histogram == other.degree_histogram
            && self.flow_histogram == other.flow_histogram
            && self.constants == other.constants
            && self.known_callees == other.known_callees
            && self.unknown_direct_calls == other.unknown_direct_calls
            && self.indirect_calls == other.indirect_calls
    }

    fn identity_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.profile
            .cmp(&other.profile)
            .then_with(|| self.extent_bytes.cmp(&other.extent_bytes))
            .then_with(|| self.code_bytes.cmp(&other.code_bytes))
            .then_with(|| self.instructions.cmp(&other.instructions))
            .then_with(|| self.blocks.cmp(&other.blocks))
            .then_with(|| self.degree_histogram.cmp(&other.degree_histogram))
            .then_with(|| self.flow_histogram.cmp(&other.flow_histogram))
            .then_with(|| self.constants.cmp(&other.constants))
            .then_with(|| self.known_callees.cmp(&other.known_callees))
            .then_with(|| self.unknown_direct_calls.cmp(&other.unknown_direct_calls))
            .then_with(|| self.indirect_calls.cmp(&other.indirect_calls))
    }
}

/// Decode a projection without consulting any function symbol, source label, target name or debug extent.
/// `known_callees` must contain only already-known proposals/imports/analyst names, not evaluation gold.
pub fn extract_features(
    binary: &Binary,
    projection: &CodeProjection,
    known_callees: &BTreeMap<u64, KnownCallee>,
) -> Result<FuzzyFeatures, FuzzyError> {
    let size = projection
        .extent
        .end
        .checked_sub(projection.extent.start)
        .filter(|size| *size > 0 && *size <= MAX_EXTENT_BYTES)
        .ok_or(FuzzyError::Evidence("extent bound"))?;
    binary.read(projection.extent.start, size).ok_or(FuzzyError::Evidence("extent not fully file-backed"))?;
    let target = binary.target();
    extract_with(
        &target,
        projection,
        |range| {
            let size = usize::try_from(range.end.checked_sub(range.start)?).ok()?;
            binary.code_from(range.start)?.get(..size)
        },
        |value| {
            if binary.segments.is_empty() {
                binary
                    .sections
                    .iter()
                    .filter(|section| section.kind != rampage_loaders::SectionKind::Other)
                    .any(|section| value >= section.address && value - section.address < section.size)
            } else {
                binary
                    .segments
                    .iter()
                    .filter(|segment| segment.perms.read || segment.perms.write || segment.perms.execute)
                    .any(|segment| value >= segment.address && value - segment.address < segment.size)
            }
        },
        known_callees,
    )
}

fn extract_with<'a>(
    target: &Target,
    projection: &CodeProjection,
    bytes: impl Fn(&Range<u64>) -> Option<&'a [u8]>,
    is_image_address: impl Fn(u64) -> bool,
    known_callees: &BTreeMap<u64, KnownCallee>,
) -> Result<FuzzyFeatures, FuzzyError> {
    let extent_bytes = projection
        .extent
        .end
        .checked_sub(projection.extent.start)
        .filter(|size| *size > 0 && *size <= MAX_EXTENT_BYTES)
        .ok_or(FuzzyError::Evidence("extent bound"))?;
    if projection.blocks.len() < MIN_BLOCKS as usize || projection.blocks.len() > MAX_BLOCKS {
        return Err(FuzzyError::Evidence("block bound"));
    }
    if projection.edges.len() > MAX_BLOCKS * MAX_BLOCKS {
        return Err(FuzzyError::Evidence("edge bound"));
    }
    if projection.retained_code_modes.len() > MAX_INSTRUCTIONS as usize
        || projection.resolved_flows.len() > MAX_INSTRUCTIONS as usize
    {
        return Err(FuzzyError::Evidence("production evidence count bound"));
    }
    let modes: BTreeMap<_, _> = projection.retained_code_modes.iter().copied().collect();
    let flows: BTreeMap<_, _> = projection.resolved_flows.iter().copied().collect();
    if modes.len() != projection.retained_code_modes.len()
        || flows.len() != projection.resolved_flows.len()
        || (target.arch != rampage_arch::Arch::Arm && !modes.is_empty())
    {
        return Err(FuzzyError::Evidence("duplicate or non-ARM mode evidence"));
    }
    let mut boundaries = BTreeSet::new();
    let mut incoming = vec![0usize; projection.blocks.len()];
    let mut outgoing = incoming.clone();
    let mut edges = BTreeSet::new();
    for &(from, to) in &projection.edges {
        if from >= incoming.len() || to >= incoming.len() || !edges.insert((from, to)) {
            return Err(FuzzyError::Evidence("edge indices or duplicate edges"));
        }
        outgoing[from] += 1;
        incoming[to] += 1;
    }
    if projection.blocks[0].start != projection.extent.start {
        return Err(FuzzyError::Evidence("entry block does not start the function extent"));
    }
    let mut reachable = BTreeSet::from([0]);
    let mut pending = vec![0];
    let mut successors = vec![Vec::new(); projection.blocks.len()];
    for &(from, to) in &projection.edges {
        successors[from].push(to);
    }
    while let Some(from) = pending.pop() {
        for &to in &successors[from] {
            if reachable.insert(to) {
                pending.push(to);
            }
        }
    }
    if reachable.len() != projection.blocks.len() {
        return Err(FuzzyError::Evidence("disconnected CFG blocks"));
    }
    let mut features = FuzzyFeatures {
        profile: FuzzyProfile::from_target(target, projection.extent.start),
        extent_bytes,
        code_bytes: 0,
        instructions: 0,
        blocks: projection.blocks.len() as u32,
        degree_histogram: [0; 16],
        flow_histogram: [0; 8],
        constants: BTreeSet::new(),
        known_callees: BTreeMap::new(),
        callee_provenance: BTreeMap::new(),
        unknown_direct_calls: 0,
        indirect_calls: 0,
        retained_flow_count: flows.len() as u32,
        retained_mode_count: modes.len() as u32,
    };
    let mut decoder = rampage_arch::decoder(target).map_err(|_| FuzzyError::Evidence("unsupported decoder"))?;
    decoder.set_code_modes(&projection.retained_code_modes);
    let mut previous_end = projection.extent.start;
    for (index, range) in projection.blocks.iter().enumerate() {
        if range.start < previous_end || range.start >= range.end || range.end > projection.extent.end {
            return Err(FuzzyError::Evidence("unsorted, overlapping or out-of-extent blocks"));
        }
        previous_end = range.end;
        features.degree_histogram[incoming[index].min(3) * 4 + outgoing[index].min(3)] += 1;
        let code = bytes(range)
            .filter(|code| code.len() as u64 == range.end - range.start)
            .ok_or(FuzzyError::Evidence("block not fully file-backed code"))?;
        features.code_bytes += code.len() as u64;
        decoder.begin_run();
        let mut offset = 0usize;
        while offset < code.len() {
            if features.instructions == MAX_INSTRUCTIONS {
                return Err(FuzzyError::Evidence("instruction bound (not a truncated descriptor)"));
            }
            let address = range.start + offset as u64;
            let instruction = decoder.decode(&code[offset..], address);
            let size = usize::from(instruction.len);
            if size == 0 || size > code.len() - offset || instruction.flow == Flow::Invalid {
                return Err(FuzzyError::Evidence("invalid or partial instruction"));
            }
            boundaries.insert(address);
            let actual_thumb = decoder.instruction_mode().unwrap_or(false);
            if features.instructions == 0 {
                features.profile.thumb = actual_thumb;
            } else if features.profile.thumb != actual_thumb {
                return Err(FuzzyError::Evidence("mixed effective instruction modes"));
            }
            let flow = validated_production_flow(instruction.flow, flows.get(&address).copied())?;
            features.instructions += 1;
            let flow_index = match flow {
                Flow::Next => 0,
                Flow::Jump(_) => 1,
                Flow::ConditionalJump(_) => 2,
                Flow::Call(callee) => {
                    if let Some(known) = known_callees.get(&callee) {
                        let name = normalize_callee(&known.name)?;
                        *features.known_callees.entry(name.clone()).or_default() += 1;
                        features.callee_provenance.insert(name, known.provenance);
                        if features.known_callees.len() > MAX_CALLEES {
                            return Err(FuzzyError::Evidence("known callee bound"));
                        }
                    } else {
                        features.unknown_direct_calls += 1;
                    }
                    3
                }
                Flow::IndirectJump => 4,
                Flow::IndirectCall => {
                    features.indirect_calls += 1;
                    5
                }
                Flow::Return => 6,
                Flow::Halt => 7,
                Flow::Invalid => unreachable!(),
            };
            features.flow_histogram[flow_index] += 1;
            // Decoder pointer candidates, address formation, displacements and branch operands are not scalars.
            // Unsupported operand evidence earns no constants; never substitute rendered text or pointer hints.
            if flow == Flow::Next && instruction.data_ref.is_none() && instruction.immediate.is_none() {
                let operands = decoder.operands(&code[offset..offset + size], address);
                let values: Vec<u64> = match operands {
                    Some(operands) => operands
                        .into_iter()
                        .filter(|operand| operand.kind == OperandKind::Immediate && operand.memory.is_none())
                        .filter_map(|operand| operand.immediate)
                        .collect(),
                    None => Vec::new(),
                };
                for value in values {
                    if value > 1 && !is_image_address(value) {
                        features.constants.insert(value);
                        if features.constants.len() > MAX_CONSTANTS {
                            return Err(FuzzyError::Evidence("constant bound (not truncated)"));
                        }
                    }
                }
            }
            offset += size;
        }
    }
    if modes.keys().chain(flows.keys()).any(|address| !boundaries.contains(address)) {
        return Err(FuzzyError::Evidence("production evidence is not on a decoded instruction boundary"));
    }
    features.validate()?;
    Ok(features)
}

fn valid_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_TEXT_BYTES && !text.chars().any(char::is_control)
}

fn normalize_callee(name: &str) -> Result<String, FuzzyError> {
    if !valid_text(name) {
        return Err(FuzzyError::Evidence("callee name bound"));
    }
    // Remove only the linker's PLT suffix; do not merge C++ names or architecture-specific leading underscores.
    let name = name.strip_suffix("@plt").unwrap_or(name);
    if !valid_text(name) {
        return Err(FuzzyError::Evidence("empty normalized callee"));
    }
    Ok(name.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceProvenance {
    pub library: String,
    /// Identifies original archive/source and build flags, not a recognition-rate promise.
    pub source: String,
    /// References, calibration and held-out queries must use distinct artifact/cohort IDs.
    pub cohort: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
}

impl ReferenceProvenance {
    fn validate(&self) -> Result<(), FuzzyError> {
        if [&self.library, &self.source, &self.cohort].into_iter().any(|text| !valid_text(text)) {
            return Err(FuzzyError::Evidence("reference provenance bound"));
        }
        if [&self.image_sha256, &self.executable_sha256]
            .into_iter()
            .flatten()
            .any(|hash| hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(FuzzyError::Evidence("reference image hash"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzyReference {
    pub name: String,
    pub provenance: ReferenceProvenance,
    pub features: FuzzyFeatures,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScoreComponents {
    pub cfg: f64,
    pub constants: f64,
    pub calls: f64,
    pub size: f64,
    pub flow: f64,
    pub total: f64,
}

fn ratio(left: u64, right: u64) -> f64 {
    if left == 0 && right == 0 { 1.0 } else { left.min(right) as f64 / left.max(right) as f64 }
}

fn histogram(left: &[u32], right: &[u32]) -> f64 {
    let left_total = left.iter().map(|value| f64::from(*value)).sum::<f64>();
    let right_total = right.iter().map(|value| f64::from(*value)).sum::<f64>();
    if left_total == 0.0 || right_total == 0.0 {
        return 0.0;
    }
    left.iter()
        .zip(right)
        .map(|(a, b)| (f64::from(*a) / left_total).min(f64::from(*b) / right_total))
        .sum::<f64>()
        .clamp(0.0, 1.0)
}

/// Fixed weights: CFG .30, constants .30, calls .20, size .10, flow .10.
/// Missing discriminating evidence earns zero, not a perfect similarity for two empty sets.
fn similarity(left: &FuzzyFeatures, right: &FuzzyFeatures) -> Option<ScoreComponents> {
    if left.profile != right.profile
        || ratio(left.extent_bytes, right.extent_bytes) < 0.25
        || ratio(u64::from(left.instructions), u64::from(right.instructions)) < 0.25
        || ratio(u64::from(left.blocks), u64::from(right.blocks)) < 0.20
    {
        return None;
    }
    let cfg = histogram(&left.degree_histogram, &right.degree_histogram);
    let union = left.constants.union(&right.constants).count();
    let constants =
        if union == 0 { 0.0 } else { left.constants.intersection(&right.constants).count() as f64 / union as f64 };
    let names: BTreeSet<&String> = left.known_callees.keys().chain(right.known_callees.keys()).collect();
    let (mut intersection, mut union) = (0u64, 0u64);
    for name in names {
        let a = u64::from(*left.known_callees.get(name).unwrap_or(&0));
        let b = u64::from(*right.known_callees.get(name).unwrap_or(&0));
        intersection += a.min(b);
        union += a.max(b);
    }
    let known_calls = if union == 0 { 0.0 } else { intersection as f64 / union as f64 };
    let unknown_calls = if left.unknown_direct_calls + left.indirect_calls == 0
        && right.unknown_direct_calls + right.indirect_calls == 0
    {
        0.0
    } else {
        0.5 * ratio(u64::from(left.unknown_direct_calls), u64::from(right.unknown_direct_calls))
            + 0.5 * ratio(u64::from(left.indirect_calls), u64::from(right.indirect_calls))
    };
    let calls = 0.8 * known_calls + 0.2 * unknown_calls;
    let size = (ratio(left.extent_bytes, right.extent_bytes)
        + ratio(left.code_bytes, right.code_bytes)
        + ratio(u64::from(left.instructions), u64::from(right.instructions)))
        / 3.0;
    let flow = histogram(&left.flow_histogram, &right.flow_histogram);
    let total = (0.30 * cfg + 0.30 * constants + 0.20 * calls + 0.10 * size + 0.10 * flow).clamp(0.0, 1.0);
    Some(ScoreComponents { cfg, constants, calls, size, flow, total })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationPolicy {
    pub profile: FuzzyProfile,
    pub threshold: f64,
    pub margin: f64,
    pub cohort: String,
    pub positives: usize,
    pub negatives: usize,
    pub correct_eligible: usize,
    pub incorrect_eligible: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzyDb {
    schema: u32,
    references: Vec<FuzzyReference>,
    calibration: Option<CalibrationPolicy>,
    /// Rebuilt from descriptors on load. Conflicting names tombstone every variant in that identity group.
    #[serde(skip)]
    ambiguous_references: BTreeSet<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateDisposition {
    Uncalibrated,
    BelowThreshold,
    AmbiguousFeatures,
    InsufficientMargin,
    /// Proposal only: not permission to persist a name or replace existing exact/analyst evidence.
    EligibleProposal,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzyCandidate {
    pub name: String,
    pub reference: ReferenceProvenance,
    pub score: ScoreComponents,
    pub rank: usize,
    pub margin_to_next_name: f64,
    pub identical_feature_collision: bool,
    pub disposition: CandidateDisposition,
    pub reference_known_callees: BTreeMap<String, CalleeProvenance>,
    pub shared_constants: Vec<u64>,
    pub shared_known_callees: Vec<String>,
    pub reference_instructions: u32,
    pub reference_blocks: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzyMatchReport {
    pub method: &'static str,
    pub confidence_interpretation: &'static str,
    pub profile: FuzzyProfile,
    pub threshold: Option<f64>,
    pub required_margin: Option<f64>,
    pub calibration_cohort: Option<String>,
    pub compared_references: usize,
    pub target_instructions: u32,
    pub target_blocks: u32,
    pub target_constant_count: usize,
    pub target_known_callees: BTreeMap<String, CalleeProvenance>,
    pub target_unknown_direct_calls: u32,
    pub target_indirect_calls: u32,
    pub target_retained_flow_count: u32,
    pub target_retained_mode_count: u32,
    pub candidates: Vec<FuzzyCandidate>,
}

/// Calibration labels belong only to the separate calibration cohort, never the held-out target cohort.
pub struct CalibrationSample<'a> {
    pub features: &'a FuzzyFeatures,
    pub expected_reference_name: Option<&'a str>,
}

impl FuzzyDb {
    pub fn new(references: Vec<FuzzyReference>) -> Result<Self, FuzzyError> {
        let mut db = Self { schema: SCHEMA, references, calibration: None, ambiguous_references: BTreeSet::new() };
        db.validate()?;
        bounded_json(&db)?;
        db.rebuild_collisions();
        Ok(db)
    }

    fn rebuild_collisions(&mut self) {
        self.ambiguous_references.clear();
        let mut indices: Vec<usize> = (0..self.references.len()).collect();
        indices.sort_by(|a, b| self.references[*a].features.identity_cmp(&self.references[*b].features));
        let mut start = 0;
        while start < indices.len() {
            let first = &self.references[indices[start]];
            let mut end = start + 1;
            while end < indices.len() && first.features.same_identity_features(&self.references[indices[end]].features)
            {
                end += 1;
            }
            if indices[start..end].iter().any(|index| self.references[*index].name != first.name) {
                self.ambiguous_references.extend(indices[start..end].iter().copied());
            }
            start = end;
        }
    }

    fn validate(&self) -> Result<(), FuzzyError> {
        if self.schema != SCHEMA || self.references.is_empty() || self.references.len() > MAX_RECORDS {
            return Err(FuzzyError::Evidence("schema or reference count"));
        }
        for reference in &self.references {
            if !valid_text(&reference.name) {
                return Err(FuzzyError::Evidence("reference name bound"));
            }
            reference.provenance.validate()?;
            reference.features.validate()?;
        }
        if let Some(policy) = &self.calibration
            && (!valid_policy_numbers(policy.threshold, policy.margin)
                || !valid_text(&policy.cohort)
                || policy.positives == 0
                || policy.negatives == 0
                || policy.positives.saturating_add(policy.negatives) > 4096
                || policy.incorrect_eligible != 0
                || policy.correct_eligible == 0
                || policy.correct_eligible > policy.positives
                || self.references.iter().any(|reference| reference.provenance.cohort == policy.cohort)
                || !self.references.iter().any(|reference| reference.features.profile == policy.profile))
        {
            return Err(FuzzyError::Evidence("invalid calibration policy"));
        }
        Ok(())
    }

    /// Bounded standalone schema; does not reinterpret or modify SignatureDb JSON/hash schemes.
    pub fn load_json(bytes: &[u8]) -> Result<Self, FuzzyError> {
        if bytes.len() > MAX_JSON_BYTES {
            return Err(FuzzyError::Evidence("JSON exceeds 64 MiB"));
        }
        #[derive(Deserialize)]
        struct StoredDb {
            schema: u32,
            references: Vec<FuzzyReference>,
            calibration: Option<CalibrationPolicy>,
        }
        let stored: StoredDb = serde_json::from_slice(bytes)?;
        let mut db = Self {
            schema: stored.schema,
            references: stored.references,
            calibration: stored.calibration,
            ambiguous_references: BTreeSet::new(),
        };
        db.validate()?;
        db.rebuild_collisions();
        Ok(db)
    }

    pub fn save_json(&self) -> Result<Vec<u8>, FuzzyError> {
        self.validate()?;
        bounded_json(self)
    }

    /// Fix the policy using positive AND negative calibration samples, before looking at held-out answers.
    /// Chooses the policy with most correct eligible predictions and zero incorrect eligible predictions;
    /// ties prefer the larger threshold/margin. Failure leaves a previously uncalibrated DB candidate-only.
    /// This is measured cohort evidence, not a statistical false-positive guarantee or source authentication.
    pub fn calibrate(
        &mut self,
        cohort: &str,
        samples: &[CalibrationSample<'_>],
        thresholds: &[f64],
        margins: &[f64],
    ) -> Result<CalibrationPolicy, FuzzyError> {
        if self.calibration.is_some() {
            return Err(FuzzyError::Evidence("policy already fixed; create a new DB to recalibrate"));
        }
        if !valid_text(cohort)
            || self.references.iter().any(|reference| reference.provenance.cohort == cohort)
            || samples.len() > 4096
            || thresholds.is_empty()
            || thresholds.len() > 32
            || samples.len().saturating_mul(self.references.len()) > 10_000_000
            || margins.is_empty()
            || margins.len() > 32
            || thresholds.iter().any(|value| !valid_policy_numbers(*value, 0.0))
            || margins.iter().any(|value| !valid_policy_numbers(1.0, *value))
        {
            return Err(FuzzyError::Evidence("calibration cohort/grid bound"));
        }
        let positives = samples.iter().filter(|sample| sample.expected_reference_name.is_some()).count();
        let negatives = samples.len() - positives;
        if positives == 0 || negatives == 0 {
            return Err(FuzzyError::Evidence("calibration requires positive and negative samples"));
        }
        let profile = samples[0].features.profile.clone();
        if samples.iter().any(|sample| sample.features.profile != profile) {
            return Err(FuzzyError::Evidence("calibration requires a single ISA/endianness/mode profile"));
        }
        let mut predictions = Vec::with_capacity(samples.len());
        for sample in samples {
            sample.features.validate()?;
            if let Some(expected) = sample.expected_reference_name
                && !self.references.iter().any(|reference| reference.name == expected)
            {
                return Err(FuzzyError::Evidence("calibration positive absent from references"));
            }
            predictions.push(self.rank(sample.features).0);
        }
        let mut best: Option<CalibrationPolicy> = None;
        for &threshold in thresholds {
            for &margin in margins {
                let mut correct = 0;
                let mut incorrect = 0;
                for (candidates, sample) in predictions.iter().zip(samples) {
                    let Some(top) = candidates.first() else { continue };
                    if !top.identical_feature_collision
                        && top.score.total >= threshold
                        && top.margin_to_next_name > 0.0
                        && top.margin_to_next_name >= margin
                    {
                        if sample.expected_reference_name == Some(top.name.as_str()) {
                            correct += 1;
                        } else {
                            incorrect += 1;
                        }
                    }
                }
                if incorrect != 0 || correct == 0 {
                    continue;
                }
                let replace = best
                    .as_ref()
                    .is_none_or(|old| (correct, threshold, margin) > (old.correct_eligible, old.threshold, old.margin));
                if replace {
                    best = Some(CalibrationPolicy {
                        profile: profile.clone(),
                        threshold,
                        margin,
                        cohort: cohort.to_owned(),
                        positives,
                        negatives,
                        correct_eligible: correct,
                        incorrect_eligible: incorrect,
                    });
                }
            }
        }
        let policy = best.ok_or(FuzzyError::Evidence("no calibration policy separates positive/negative evidence"))?;
        self.calibration = Some(policy.clone());
        Ok(policy)
    }

    /// Query descriptors must have no target function names and use discovery extents, not gold sizes.
    /// Rank/margin is computed against ALL compatible references before truncating to at most 16 names.
    pub fn candidates(
        &self,
        features: &FuzzyFeatures,
        query_cohort: &str,
        limit: usize,
    ) -> Result<FuzzyMatchReport, FuzzyError> {
        features.validate()?;
        self.validate_query_cohort(query_cohort)?;
        if !(1..=16).contains(&limit) {
            return Err(FuzzyError::Evidence("query candidate limit"));
        }
        let (mut candidates, compared) = self.rank(features);
        let policy = self.calibration.as_ref().filter(|policy| policy.profile == features.profile);
        for candidate in &mut candidates {
            candidate.disposition = match policy {
                _ if candidate.identical_feature_collision => CandidateDisposition::AmbiguousFeatures,
                None => CandidateDisposition::Uncalibrated,
                Some(policy) if candidate.score.total < policy.threshold => CandidateDisposition::BelowThreshold,
                Some(policy)
                    if candidate.rank != 1
                        || candidate.margin_to_next_name <= 0.0
                        || candidate.margin_to_next_name < policy.margin =>
                {
                    CandidateDisposition::InsufficientMargin
                }
                Some(_) => CandidateDisposition::EligibleProposal,
            };
        }
        candidates.truncate(limit);
        Ok(FuzzyMatchReport {
            method: "secondary_cfg_constants_calls_v1",
            confidence_interpretation: "bounded similarity, not probability; candidates never persist names",
            profile: features.profile.clone(),
            threshold: policy.map(|policy| policy.threshold),
            required_margin: policy.map(|policy| policy.margin),
            calibration_cohort: policy.map(|policy| policy.cohort.clone()),
            compared_references: compared,
            target_instructions: features.instructions,
            target_blocks: features.blocks,
            target_constant_count: features.constants.len(),
            target_known_callees: features.callee_provenance.clone(),
            target_unknown_direct_calls: features.unknown_direct_calls,
            target_indirect_calls: features.indirect_calls,
            target_retained_flow_count: features.retained_flow_count,
            target_retained_mode_count: features.retained_mode_count,
            candidates,
        })
    }

    pub fn validate_query_cohort(&self, query_cohort: &str) -> Result<(), FuzzyError> {
        if !valid_text(query_cohort)
            || self.references.iter().any(|reference| reference.provenance.cohort == query_cohort)
            || self.calibration.as_ref().is_some_and(|policy| policy.cohort == query_cohort)
        {
            return Err(FuzzyError::Evidence("query must use a distinct held-out cohort"));
        }
        Ok(())
    }

    pub fn validate_executable_cohort(&self, executable_sha256: &str) -> Result<(), FuzzyError> {
        if executable_sha256.len() != 64
            || !executable_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self
                .references
                .iter()
                .any(|reference| reference.provenance.executable_sha256.as_deref() == Some(executable_sha256))
            || self.calibration.as_ref().is_some_and(|policy| policy.cohort == executable_sha256)
        {
            return Err(FuzzyError::Evidence("executable code duplicates a reference/calibration cohort"));
        }
        Ok(())
    }

    fn rank(&self, features: &FuzzyFeatures) -> (Vec<FuzzyCandidate>, usize) {
        let mut names: BTreeMap<&str, (usize, &FuzzyReference, ScoreComponents)> = BTreeMap::new();
        let mut compared = 0;
        for (index, reference) in self.references.iter().enumerate() {
            let Some(score) = similarity(features, &reference.features) else { continue };
            compared += 1;
            let entry = names.entry(&reference.name).or_insert((index, reference, score));
            if score.total > entry.2.total {
                *entry = (index, reference, score);
            }
        }
        let mut ranked: Vec<_> = names.into_values().collect();
        ranked.sort_by(|(_, a, a_score), (_, b, b_score)| {
            b_score.total.total_cmp(&a_score.total).then_with(|| a.name.cmp(&b.name))
        });
        let candidates = ranked
            .iter()
            .take(16)
            .enumerate()
            .map(|(index, (reference_index, reference, score))| {
                let collision = self.ambiguous_references.contains(reference_index);
                let next_score = ranked.get(index + 1).map_or(0.0, |(_, _, next)| next.total);
                FuzzyCandidate {
                    name: reference.name.clone(),
                    reference: reference.provenance.clone(),
                    score: *score,
                    rank: index + 1,
                    margin_to_next_name: (score.total - next_score).clamp(0.0, 1.0),
                    identical_feature_collision: collision,
                    disposition: CandidateDisposition::Uncalibrated,
                    reference_known_callees: reference.features.callee_provenance.clone(),
                    shared_constants: features.constants.intersection(&reference.features.constants).copied().collect(),
                    shared_known_callees: features
                        .known_callees
                        .keys()
                        .filter(|name| reference.features.known_callees.contains_key(*name))
                        .cloned()
                        .collect(),
                    reference_instructions: reference.features.instructions,
                    reference_blocks: reference.features.blocks,
                }
            })
            .collect();
        (candidates, compared)
    }
}

fn valid_policy_numbers(threshold: f64, margin: f64) -> bool {
    threshold.is_finite() && margin.is_finite() && (0.0..=1.0).contains(&threshold) && (0.0..=1.0).contains(&margin)
}

fn bounded_json(db: &FuzzyDb) -> Result<Vec<u8>, FuzzyError> {
    struct BoundedWriter {
        bytes: Vec<u8>,
        exceeded: bool,
    }
    impl std::io::Write for BoundedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_JSON_BYTES.saturating_sub(self.bytes.len()) {
                self.exceeded = true;
                return Err(std::io::Error::other("fuzzy JSON exceeds 64 MiB"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = BoundedWriter { bytes: Vec::new(), exceeded: false };
    let result = serde_json::to_writer(&mut writer, db);
    if writer.exceeded {
        return Err(FuzzyError::Evidence("JSON exceeds 64 MiB"));
    }
    result?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(constants: &[u64]) -> FuzzyFeatures {
        FuzzyFeatures {
            profile: FuzzyProfile::from_target(&Target::new(rampage_arch::Arch::X86_64), 0x4000),
            extent_bytes: 80,
            code_bytes: 80,
            instructions: 20,
            blocks: 2,
            degree_histogram: [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flow_histogram: [18, 0, 1, 0, 0, 0, 1, 0],
            constants: constants.iter().copied().collect(),
            known_callees: BTreeMap::new(),
            callee_provenance: BTreeMap::new(),
            unknown_direct_calls: 0,
            indirect_calls: 0,
            retained_flow_count: 0,
            retained_mode_count: 0,
        }
    }

    fn reference(name: &str, features: FuzzyFeatures) -> FuzzyReference {
        FuzzyReference {
            name: name.to_owned(),
            features,
            provenance: ReferenceProvenance {
                library: "owned test library".to_owned(),
                source: "source.c, O1; synthetic descriptor test, not corpus measurement".to_owned(),
                cohort: "reference".to_owned(),
                image_sha256: None,
                executable_sha256: None,
            },
        }
    }

    #[test]
    fn near_miss_reports_components_but_uncalibrated_never_eligible() {
        let original = descriptor(&[23, 37, 91]);
        let db = FuzzyDb::new(vec![reference("library_loop", original.clone())]).unwrap();
        let mut changed = original;
        changed.instructions += 3;
        changed.flow_histogram[0] += 3;
        changed.code_bytes += 9;
        changed.extent_bytes += 9;
        let report = db.candidates(&changed, "heldout", 1).unwrap();
        let candidate = &report.candidates[0];
        assert!(candidate.score.total > 0.6 && candidate.score.total < 1.0);
        for score in [
            candidate.score.cfg,
            candidate.score.constants,
            candidate.score.calls,
            candidate.score.size,
            candidate.score.flow,
            candidate.score.total,
        ] {
            assert!(score.is_finite() && (0.0..=1.0).contains(&score));
        }
        assert!(matches!(candidate.disposition, CandidateDisposition::Uncalibrated));
        assert_eq!(candidate.shared_constants, vec![23, 37, 91]);
        assert!(report.threshold.is_none());
    }

    #[test]
    fn colliding_names_remain_ambiguous_after_serialization_and_limit_one() {
        let features = descriptor(&[23, 37, 91]);
        let db =
            FuzzyDb::new(vec![reference("first", features.clone()), reference("second", features.clone())]).unwrap();
        let db = FuzzyDb::load_json(&db.save_json().unwrap()).unwrap();
        let report = db.candidates(&features, "heldout", 1).unwrap();
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].margin_to_next_name, 0.0);
        assert!(report.candidates[0].identical_feature_collision);
        assert!(matches!(report.candidates[0].disposition, CandidateDisposition::AmbiguousFeatures));
    }

    #[test]
    fn calibration_fixed_before_heldout_and_negatives_do_not_receive_names() {
        let positive = descriptor(&[23, 37, 91]);
        let negative = descriptor(&[101, 103, 107]);
        let mut db = FuzzyDb::new(vec![reference("owned", positive.clone())]).unwrap();
        let policy = db
            .calibrate(
                "calibration",
                &[
                    CalibrationSample { features: &positive, expected_reference_name: Some("owned") },
                    CalibrationSample { features: &negative, expected_reference_name: None },
                ],
                &[0.6, 0.7],
                &[0.05, 0.1],
            )
            .unwrap();
        assert_eq!(policy.correct_eligible, 1);
        let eligible = db.candidates(&positive, "heldout", 1).unwrap();
        assert!(matches!(eligible.candidates[0].disposition, CandidateDisposition::EligibleProposal));
        let rejected = db.candidates(&negative, "heldout", 1).unwrap();
        assert!(matches!(rejected.candidates[0].disposition, CandidateDisposition::BelowThreshold));
        assert!(db.candidates(&positive, "calibration", 1).is_err());
        assert!(db.candidates(&positive, "reference", 1).is_err());
        assert!(db.calibrate("second", &[], &[0.0], &[0.0]).is_err());
        let loaded = FuzzyDb::load_json(&db.save_json().unwrap()).unwrap();
        assert_eq!(loaded.candidates(&positive, "heldout", 1).unwrap().threshold, Some(policy.threshold));
    }

    #[test]
    fn indistinguishable_negative_prevents_calibration() {
        let features = descriptor(&[23, 37, 91]);
        let mut db = FuzzyDb::new(vec![reference("owned", features.clone())]).unwrap();
        assert!(
            db.calibrate(
                "calibration",
                &[
                    CalibrationSample { features: &features, expected_reference_name: Some("owned") },
                    CalibrationSample { features: &features, expected_reference_name: None },
                ],
                &[0.1, 0.7, 0.95],
                &[0.0, 0.1]
            )
            .is_err()
        );
        assert!(db.calibration.is_none());
    }

    #[test]
    fn rank_margin_sees_unreturned_distinct_name_but_not_same_name_variants() {
        let original = descriptor(&[23, 37, 91]);
        let mut variant = original.clone();
        variant.extent_bytes += 1;
        let db = FuzzyDb::new(vec![reference("owned", original.clone()), reference("owned", variant)]).unwrap();
        assert!(db.candidates(&original, "heldout", 1).unwrap().candidates[0].margin_to_next_name > 0.0);
        let db =
            FuzzyDb::new(vec![reference("owned", original.clone()), reference("unrelated", descriptor(&[23, 37, 92]))])
                .unwrap();
        let one = db.candidates(&original, "heldout", 1).unwrap();
        let two = db.candidates(&original, "heldout", 2).unwrap();
        assert_eq!(one.candidates[0].margin_to_next_name, two.candidates[0].margin_to_next_name);
        assert!(one.candidates[0].margin_to_next_name < one.candidates[0].score.total);
    }

    #[test]
    fn isa_endianness_mode_and_size_are_hard_guards() {
        let original = descriptor(&[23, 37, 91]);
        let db = FuzzyDb::new(vec![reference("owned", original.clone())]).unwrap();
        let mut variants = vec![original.clone(); 4];
        variants[0].profile.architecture = "aarch64".to_owned();
        variants[1].profile.instruction_big_endian = true;
        variants[2].profile.data_big_endian = true;
        variants[3].extent_bytes = 1000;
        for variant in variants {
            assert!(db.candidates(&variant, "heldout", 1).unwrap().candidates.is_empty());
        }
        let mut arm = original;
        arm.profile.architecture = "arm".to_owned();
        let db = FuzzyDb::new(vec![reference("arm", arm.clone())]).unwrap();
        arm.profile.thumb = true;
        assert!(db.candidates(&arm, "heldout", 1).unwrap().candidates.is_empty());
    }

    #[test]
    fn weak_stubs_and_untrusted_json_counts_are_rejected() {
        let mut weak = descriptor(&[23, 37]);
        weak.instructions = 3;
        assert!(FuzzyDb::new(vec![reference("stub", weak)]).is_err());
        let mut weak = descriptor(&[23]);
        assert!(FuzzyDb::new(vec![reference("generic", weak.clone())]).is_err());
        weak.constants.insert(37);
        let db = FuzzyDb::new(vec![reference("owned", weak)]).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&db.save_json().unwrap()).unwrap();
        value["references"][0]["features"]["flow_histogram"][0] = serde_json::json!(4_294_967_295u32);
        assert!(FuzzyDb::load_json(&serde_json::to_vec(&value).unwrap()).is_err());
        value["schema"] = serde_json::json!(2);
        assert!(FuzzyDb::load_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    fn decoded_fixture(base: u64, insert_nop: bool) -> (Vec<u8>, CodeProjection) {
        let mut bytes = vec![
            0xb8, 23, 0, 0, 0, 0x83, 0xc0, 37, 0x83, 0xf0, 90, 0x83, 0xc0, 7, 0x83, 0xe0, 17, 0x83, 0xc0, 13, 0x85,
            0xc0, 0x75, 0,
        ];
        let boundary = bytes.len() as u64;
        if insert_nop {
            bytes.push(0x90);
        }
        bytes.extend([0x83, 0xc0, 37, 0x83, 0xf0, 90, 0x83, 0xc0, 7, 0x83, 0xe0, 17, 0x85, 0xc0, 0xc3]);
        let projection = CodeProjection {
            extent: base..base + bytes.len() as u64,
            blocks: vec![base..base + boundary, base + boundary..base + bytes.len() as u64],
            edges: vec![(0, 1)],
            retained_code_modes: Vec::new(),
            resolved_flows: Vec::new(),
        };
        (bytes, projection)
    }

    fn extract_fixture(bytes: &[u8], projection: &CodeProjection) -> Result<FuzzyFeatures, FuzzyError> {
        extract_with(
            &Target::new(rampage_arch::Arch::X86_64),
            projection,
            |range| {
                let start = usize::try_from(range.start - projection.extent.start).ok()?;
                let end = usize::try_from(range.end - projection.extent.start).ok()?;
                bytes.get(start..end)
            },
            |_| false,
            &BTreeMap::new(),
        )
    }

    #[test]
    fn real_decoder_relocation_invariance_and_changed_instruction_similarity() {
        let (bytes, projection) = decoded_fixture(0x4000, false);
        let original = extract_fixture(&bytes, &projection).unwrap();
        let (relocated_bytes, relocated) = decoded_fixture(0x9000, false);
        assert_eq!(original, extract_fixture(&relocated_bytes, &relocated).unwrap());
        let (changed_bytes, changed) = decoded_fixture(0xa000, true);
        let changed = extract_fixture(&changed_bytes, &changed).unwrap();
        assert_ne!(original, changed);
        assert!(similarity(&original, &changed).unwrap().total > 0.6);
        assert!(original.constants.contains(&23));
        assert!(original.constants.contains(&37));
        assert_eq!(original.unknown_direct_calls, 0);
    }

    #[test]
    fn partial_instructions_file_backing_overlaps_and_address_constants_fail_closed() {
        let (bytes, projection) = decoded_fixture(0x4000, false);
        assert!(extract_fixture(&bytes[..bytes.len() - 1], &projection).is_err());
        let mut overlap = projection.clone();
        overlap.blocks[1].start -= 1;
        assert!(extract_fixture(&bytes, &overlap).is_err());
        let mut split = projection.clone();
        split.blocks[0].end = split.blocks[0].start + 1;
        assert!(extract_fixture(&bytes, &split).is_err());
        let result = extract_with(
            &Target::new(rampage_arch::Arch::X86_64),
            &projection,
            |range| {
                bytes.get(
                    (range.start - projection.extent.start) as usize..(range.end - projection.extent.start) as usize,
                )
            },
            |_| true,
            &BTreeMap::new(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn unknown_calls_never_acquire_debug_names() {
        let (mut bytes, mut projection) = decoded_fixture(0x4000, false);
        bytes.splice(0..5, [0xe8, 0, 0, 0, 0]);
        let unknown = extract_fixture(&bytes, &projection).unwrap();
        assert_eq!(unknown.unknown_direct_calls, 1);
        assert!(unknown.known_callees.is_empty());
        let known = BTreeMap::from([(
            0x4005,
            KnownCallee { name: "real_import@plt".to_owned(), provenance: CalleeProvenance::Import },
        )]);
        let known = extract_with(
            &Target::new(rampage_arch::Arch::X86_64),
            &projection,
            |range| {
                bytes.get(
                    (range.start - projection.extent.start) as usize..(range.end - projection.extent.start) as usize,
                )
            },
            |_| false,
            &known,
        )
        .unwrap();
        assert_eq!(known.known_callees.get("real_import"), Some(&1));
        assert_eq!(known.unknown_direct_calls, 0);
        projection.edges.push((99, 0));
        assert!(extract_fixture(&bytes, &projection).is_err());
    }

    #[test]
    fn retained_thumb_and_arm_overrides_decode_consistently_and_mixed_modes_refuse() {
        let base = 0x4000;
        let mut thumb = Vec::new();
        for _ in 0..6 {
            thumb.extend(0x3025u16.to_le_bytes());
        }
        thumb.extend(0xd1ffu16.to_le_bytes());
        let boundary = thumb.len() as u64;
        for _ in 0..6 {
            thumb.extend(0x305bu16.to_le_bytes());
        }
        thumb.extend(0x4770u16.to_le_bytes());
        let mut projection = CodeProjection {
            extent: base..base + thumb.len() as u64,
            blocks: vec![base..base + boundary, base + boundary..base + thumb.len() as u64],
            edges: vec![(0, 1)],
            retained_code_modes: vec![(base, true), (base + boundary, true)],
            resolved_flows: Vec::new(),
        };
        let extract = |target: &Target, code: &[u8], projection: &CodeProjection| {
            extract_with(
                target,
                projection,
                |range| code.get((range.start - base) as usize..(range.end - base) as usize),
                |_| false,
                &BTreeMap::new(),
            )
        };
        let arm = Target::new(rampage_arch::Arch::Arm);
        let error = extract(&arm, &thumb, &projection).unwrap_err().to_string();
        // ARM currently has no checked scalar operand evidence; this gate is later than successful mode decoding.
        assert!(error.contains("insufficient fixed"), "{error}");
        let mut a32 = Vec::new();
        for _ in 0..6 {
            a32.extend(0xe2800025u32.to_le_bytes());
        }
        a32.extend(0x1affffffu32.to_le_bytes());
        let boundary = a32.len() as u64;
        for _ in 0..6 {
            a32.extend(0xe280005bu32.to_le_bytes());
        }
        a32.extend(0xe12fff1eu32.to_le_bytes());
        projection.extent = base..base + a32.len() as u64;
        projection.blocks = vec![base..base + boundary, base + boundary..base + a32.len() as u64];
        projection.retained_code_modes = vec![(base, false), (base + boundary, false)];
        let mut loader_thumb = arm.clone();
        loader_thumb.thumb = vec![projection.extent.clone()].into();
        let error = extract(&loader_thumb, &a32, &projection).unwrap_err().to_string();
        assert!(error.contains("insufficient fixed"), "{error}");
        let mut mixed = thumb[..14].to_vec();
        mixed.extend_from_slice(&a32[boundary as usize..]);
        projection.extent = base..base + mixed.len() as u64;
        projection.blocks = vec![base..base + 14, base + 14..projection.extent.end];
        projection.retained_code_modes = vec![(base, true), (base + 14, false)];
        assert!(extract(&arm, &mixed, &projection).unwrap_err().to_string().contains("mixed effective"));
    }

    #[test]
    fn retained_a64_indirect_call_resolution_drives_call_features_and_checks_boundaries() {
        let base = 0x4000;
        let mut words = Vec::new();
        for value in [23u32, 37, 91, 13, 17, 29] {
            words.push(0x11000000 | (value << 10));
        }
        words.push(0xd63f0120); // blr x9: unresolved when the block begins without predecessor register facts.
        words.push(0x54000020); // b.eq next block.
        let boundary = words.len() as u64 * 4;
        for value in [23u32, 37, 91, 13, 17, 29] {
            words.push(0x11000000 | (value << 10));
        }
        words.push(0xd65f03c0);
        let code: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let mut projection = CodeProjection {
            extent: base..base + code.len() as u64,
            blocks: vec![base..base + boundary, base + boundary..base + code.len() as u64],
            edges: vec![(0, 1)],
            retained_code_modes: Vec::new(),
            resolved_flows: vec![(base + 24, Flow::Call(0xdeadbeef))],
        };
        let known = BTreeMap::from([(
            0xdeadbeef,
            KnownCallee { name: "prior_exact_proposal".into(), provenance: CalleeProvenance::ExactSignatureProposal },
        )]);
        let extract = |projection: &CodeProjection| {
            extract_with(
                &Target::new(rampage_arch::Arch::Aarch64),
                projection,
                |range| code.get((range.start - base) as usize..(range.end - base) as usize),
                |_| false,
                &known,
            )
        };
        let resolved = extract(&projection).unwrap();
        assert_eq!(resolved.known_callees.get("prior_exact_proposal"), Some(&1));
        assert_eq!(resolved.indirect_calls, 0);
        projection.resolved_flows.clear();
        assert_eq!(extract(&projection).unwrap().indirect_calls, 1);
        projection.resolved_flows.push((base + 24, Flow::Jump(0xdeadbeef)));
        assert!(extract(&projection).is_err());
        projection.resolved_flows = vec![(base + 25, Flow::Call(0xdeadbeef))];
        assert!(extract(&projection).is_err());
    }

    #[test]
    fn nonallocated_metadata_at_zero_is_not_mapped_pointer_evidence() {
        let (code, projection) = decoded_fixture(0x4000, false);
        let hex: String = code.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut binary = Binary::from_snapshot_bytes(
            serde_json::to_vec(&serde_json::json!({
                "format": "rampage-snapshot-v1", "arch": "x86_64",
                "provenance": "SYNTHETIC unit-only decoder fixture; not a captured process or measured corpus binary",
                "regions": [{"name": "owned-code", "address": "0x4000", "permissions": "r-x", "bytes": hex}],
                "seeds": ["0x4000"]
            }))
            .unwrap(),
        )
        .unwrap();
        let original = extract_features(&binary, &projection, &BTreeMap::new()).unwrap();
        binary.sections.push(rampage_loaders::Section {
            name: ".strtab".into(),
            address: 0,
            size: 65536,
            kind: rampage_loaders::SectionKind::Other,
            file_offset: None,
            file_size: 0,
        });
        let with_metadata = extract_features(&binary, &projection, &BTreeMap::new()).unwrap();
        assert_eq!(original, with_metadata);
        assert!(with_metadata.constants.contains(&23));
        assert!(with_metadata.constants.contains(&37));
    }
}
