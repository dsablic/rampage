use rampage_arch::Flow;
use rampage_loaders::{Binary, Section, SectionKind};
use serde::Serialize;

use crate::triage::entropy;

#[derive(Debug, Serialize)]
pub struct Diagnostics {
    pub regions: Vec<DecodeRegion>,
    pub limitations: Vec<String>,
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
}

pub fn diagnostics(binary: &Binary) -> Diagnostics {
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
            region.assessment = "high-entropy code: disassembly and discovered functions may be unreliable";
        } else if region.instructions > 16 && region.invalid * 4 > region.instructions {
            region.assessment =
                "many invalid instructions: check architecture, mode, truncation or code/data boundaries";
        }
        regions.push(region);
    }
    Diagnostics {
        regions,
        limitations: vec![
            "Decode success is not evidence that bytes are executable code.".to_owned(),
            "Entropy is evidence of compression or transformation, not proof of encryption.".to_owned(),
            "Indirect transfers require known registers and immutable or captured pointer values.".to_owned(),
            "Static bytes do not model runtime code generation or protection wrappers.".to_owned(),
        ],
    }
}
