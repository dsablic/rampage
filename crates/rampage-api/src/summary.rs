use serde::Serialize;

use crate::{ApiError, FunctionGraph, Page, Project, XrefQuery, XrefRow};

#[derive(Debug, Serialize)]
pub struct FunctionSummary {
    pub graph: FunctionGraph,
    pub references: Page<XrefRow>,
    pub limitations: Vec<String>,
    pub ir: Vec<rampage_arch::ir::LiftedInstruction>,
    pub lifted_instructions: usize,
}

impl Project {
    pub fn function_summary(&self, address: u64) -> Result<FunctionSummary, ApiError> {
        let graph = self.function_graph(address)?;
        let references = self.xrefs(XrefQuery::From(graph.address), None, Some(1000))?;
        let mut ir = Vec::new();
        for line in graph.blocks.iter().flat_map(|block| &block.lines) {
            let bytes: Vec<_> = line
                .bytes
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
                .collect();
            let insn = rampage_arch::Insn {
                address: line.address,
                len: bytes.len() as u8,
                flow: line.flow,
                data_ref: line.data_ref,
                immediate: line.immediate,
            };
            ir.push(rampage_arch::ir::lift(self.binary.arch, &bytes, &insn));
        }
        let lifted_instructions = ir.iter().filter(|instruction| instruction.complete).count();
        Ok(FunctionSummary {
            graph,
            references,
            ir,
            lifted_instructions,
            limitations: vec![
                "This is a structural summary of decoded blocks and references, not decompiled source.".to_owned(),
                "Unknown indirect transfers and runtime-generated code are not reconstructed.".to_owned(),
                "No source-level types, variable recovery, SSA or complete instruction semantics.".to_owned(),
            ],
        })
    }
}
