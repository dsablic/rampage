use rampage_arch::Flow;
use rampage_loaders::{Binary, Section, SectionKind};
use serde::Serialize;

use crate::discover::DiscoveredFunction;
use crate::triage::entropy;

pub const TINY_CANDIDATE_INSTRUCTIONS: usize = 4;

#[derive(Debug, Serialize)]
pub struct Diagnostics {
    pub regions: Vec<DecodeRegion>,
    pub discovery: Option<DiscoveryEvidence>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryEvidence {
    pub total_candidates: usize,
    pub tiny_candidates: usize,
    pub tiny_instruction_limit: usize,
    pub candidates_in_sampled_ranges: usize,
    pub candidates_in_flagged_sampled_ranges: usize,
    pub tiny_candidates_in_flagged_sampled_ranges: usize,
    pub candidates_outside_sampled_ranges: usize,
}

#[derive(Debug, Serialize)]
pub struct SampleCandidates {
    pub candidates: usize,
    pub tiny_candidates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeSignal {
    HighEntropy,
    HighInvalidRate,
}

impl Diagnostics {
    pub fn with_discovery(mut self, functions: &[DiscoveredFunction]) -> Self {
        let mut indexed: Vec<_> = functions.iter().enumerate().collect();
        indexed.sort_unstable_by_key(|(_, function)| function.address);
        let mut sampled = vec![false; functions.len()];
        let mut flagged = vec![false; functions.len()];
        for region in &mut self.regions {
            let start = indexed.partition_point(|(_, function)| function.address < region.address);
            let slice = &indexed[start..];
            let end =
                slice.partition_point(|(_, function)| function.address - region.address < region.bytes_sampled as u64);
            let mut tiny_candidates = 0;
            for &(index, function) in &slice[..end] {
                sampled[index] = true;
                flagged[index] |= !region.signals.is_empty();
                tiny_candidates += usize::from(function.instruction_count <= TINY_CANDIDATE_INSTRUCTIONS);
            }
            region.discovery = Some(SampleCandidates { candidates: end, tiny_candidates });
        }
        let candidates_in_sampled_ranges = sampled.iter().filter(|&&value| value).count();
        self.discovery = Some(DiscoveryEvidence {
            total_candidates: functions.len(),
            tiny_candidates: functions
                .iter()
                .filter(|function| function.instruction_count <= TINY_CANDIDATE_INSTRUCTIONS)
                .count(),
            tiny_instruction_limit: TINY_CANDIDATE_INSTRUCTIONS,
            candidates_in_sampled_ranges,
            candidates_in_flagged_sampled_ranges: flagged.iter().filter(|&&value| value).count(),
            tiny_candidates_in_flagged_sampled_ranges: functions
                .iter()
                .zip(&flagged)
                .filter(|(function, flag)| **flag && function.instruction_count <= TINY_CANDIDATE_INSTRUCTIONS)
                .count(),
            candidates_outside_sampled_ranges: functions.len() - candidates_in_sampled_ranges,
        });
        self.limitations.push(
            concat!(
                "Discovery counts describe candidates, not verified functions. ",
                "Tiny candidates alone are not evidence of invalid code."
            )
            .to_owned(),
        );
        self.limitations.push(
            concat!(
                "Region signals apply only to the sampled bytes; entry membership ",
                "does not assess a candidate's entire body or unsampled code."
            )
            .to_owned(),
        );
        self
    }
}

#[derive(Debug, Serialize)]
pub struct DecodeRegion {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub bytes_sampled: usize,
    pub instructions: usize,
    pub invalid: usize,
    pub indirect_transfers: usize,
    pub external_branches: usize,
    pub entropy: f64,
    pub assessment: &'static str,
    pub signals: Vec<DecodeSignal>,
    pub discovery: Option<SampleCandidates>,
}

pub fn diagnostics(binary: &Binary) -> Diagnostics {
    diagnostics_with_modes(binary, &[])
}

pub fn diagnostics_with_modes(binary: &Binary, modes: &[(u64, bool)]) -> Diagnostics {
    let mut regions = Vec::new();
    let code: Vec<_> = binary.sections.iter().filter(|section| section.kind == SectionKind::Code).cloned().collect();
    let code = if code.is_empty() {
        binary
            .segments
            .iter()
            .filter(|segment| segment.perms.execute)
            .map(|segment| Section {
                name: segment.name.clone(),
                address: segment.address,
                size: segment.file_size,
                kind: SectionKind::Code,
                file_offset: Some(segment.file_offset),
                file_size: segment.file_size,
            })
            .collect()
    } else {
        code
    };
    for section in &code {
        let Some(code) = binary.read_to_segment_end(section.address) else { continue };
        let size = code.len().min(usize::try_from(section.size).unwrap_or(usize::MAX)).min(64 * 1024);
        let code = &code[..size];
        let Ok(mut decoder) = binary.decoder() else { continue };
        decoder.set_code_modes(modes);
        let mut region = DecodeRegion {
            name: section.name.clone(),
            address: section.address,
            bytes_sampled: size,
            instructions: 0,
            invalid: 0,
            indirect_transfers: 0,
            external_branches: 0,
            entropy: entropy(code),
            assessment: "no strong indication of transformed code",
            signals: Vec::new(),
            discovery: None,
        };
        let mut offset = 0;
        while offset < size {
            let at = section.address.saturating_add(offset as u64);
            let insn = decoder.decode(&code[offset..], at);
            region.instructions += 1;
            match insn.flow {
                Flow::Invalid => region.invalid += 1,
                Flow::IndirectJump | Flow::IndirectCall => region.indirect_transfers += 1,
                Flow::Jump(to) | Flow::Call(to) | Flow::ConditionalJump(to) if !binary.is_code(to) => {
                    region.external_branches += 1;
                }
                _ => {}
            }
            offset += usize::from(insn.len.max(1));
            decoder.reset();
        }
        if size >= 512 && region.entropy > 7.7 {
            region.signals.push(DecodeSignal::HighEntropy);
        }
        if region.instructions > 16 && region.invalid * 4 > region.instructions {
            region.signals.push(DecodeSignal::HighInvalidRate);
        }
        if region.signals.contains(&DecodeSignal::HighEntropy) {
            region.assessment = "high-entropy code: disassembly and discovered functions may be unreliable";
        } else if region.signals.contains(&DecodeSignal::HighInvalidRate) {
            region.assessment =
                "many invalid instructions: check architecture, mode, truncation or code/data boundaries";
        }
        regions.push(region);
    }
    Diagnostics {
        regions,
        discovery: None,
        limitations: vec![
            "Decode success is not evidence that bytes are executable code.".to_owned(),
            "Entropy is evidence of compression or transformation, not proof of encryption.".to_owned(),
            "Indirect transfers require known registers and immutable or captured pointer values.".to_owned(),
            "Static bytes do not model runtime code generation or protection wrappers.".to_owned(),
        ],
    }
}
