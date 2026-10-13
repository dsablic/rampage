use serde::Serialize;

use crate::{ApiError, FunctionGraph, Page, Project, XrefQuery, XrefRow};
use rampage_analysis::ssa::{self, InputBlock, Ssa};

#[derive(Debug, Serialize)]
pub struct FunctionSummary {
    pub graph: FunctionGraph,
    pub references: Page<XrefRow>,
    pub limitations: Vec<String>,
    pub ir: Vec<rampage_arch::ir::LiftedInstruction>,
    pub lifted_instructions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssa: Option<Ssa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataflow: Option<rampage_analysis::dataflow::DataFlow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pseudocode: Option<rampage_analysis::pseudocode::Pseudocode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<rampage_analysis::control::ControlFlow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_control: Option<rampage_analysis::structure::StructuredControl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_pseudocode: Option<rampage_analysis::pseudocode::Pseudocode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_evidence: Option<rampage_analysis::type_evidence::TypeEvidence>,
    pub validated_indirect_targets: Vec<rampage_analysis::dataflow::IndirectTarget>,
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
                conditional: false,
            };
            ir.push(rampage_arch::ir::lift(self.binary.arch, &bytes, &insn));
        }
        let lifted_instructions = ir.iter().filter(|instruction| instruction.complete).count();
        let mut limitations = vec![
            "This is a structural summary of decoded blocks and references, not decompiled source.".to_owned(),
            "Unknown indirect transfers and runtime-generated code are not reconstructed.".to_owned(),
            "No source-level types, variable recovery or complete instruction semantics.".to_owned(),
        ];
        let ssa = if self.binary.arch == rampage_arch::Arch::Aarch64 {
            let mut offset = 0;
            let blocks: Vec<_> = graph
                .blocks
                .iter()
                .map(|block| {
                    let end = offset + block.lines.len();
                    let instructions = ir[offset..end].to_vec();
                    offset = end;
                    InputBlock { address: block.start, instructions }
                })
                .collect();
            let edges: Vec<_> = graph.edges.iter().map(|edge| (edge.from, edge.to)).collect();
            let result = graph
                .entry()
                .ok_or_else(|| "graph has no entry block".to_owned())
                .and_then(|entry| ssa::build(&blocks, &edges, entry));
            match result {
                Ok(mut ssa) => {
                    if let Err(error) = ssa::simplify(&mut ssa) {
                        limitations.push(format!("SSA simplification omitted: {error}"));
                    }
                    Some(ssa)
                }
                Err(error) => {
                    limitations.push(format!("SSA omitted: {error}"));
                    None
                }
            }
        } else {
            None
        };
        let dataflow = match ssa.as_ref().map(rampage_analysis::dataflow::analyze).transpose() {
            Ok(dataflow) => dataflow,
            Err(error) => {
                limitations.push(format!("Dataflow omitted: {error}"));
                None
            }
        };
        let type_evidence = match ssa.as_ref().map(rampage_analysis::type_evidence::analyze).transpose() {
            Ok(evidence) => evidence,
            Err(error) => {
                limitations.push(format!("Type evidence omitted: {error}"));
                None
            }
        };
        let validated_indirect_targets = dataflow
            .as_ref()
            .map(|data| {
                data.indirect_targets
                    .iter()
                    .filter_map(|evidence| {
                        if evidence.target == 0
                            || evidence.target % 4 != 0
                            || !self.binary.is_code(evidence.target)
                            || self
                                .binary
                                .segment_containing(evidence.target)
                                .is_none_or(|segment| !segment.perms.execute || !segment.perms.read)
                        {
                            return None;
                        }
                        let bytes = self.binary.code_from(evidence.target)?.get(..4)?;
                        let instruction = self.binary.decoder().ok()?.decode(bytes, evidence.target);
                        if instruction.flow == rampage_arch::Flow::Invalid {
                            return None;
                        }
                        Some(rampage_analysis::dataflow::IndirectTarget {
                            address: evidence.address,
                            target: evidence.target,
                            call: evidence.call,
                            input_definitions: evidence.input_definitions.clone(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let edges: Vec<_> = graph.edges.iter().map(|edge| (edge.from, edge.to)).collect();
        let control = match ssa.as_ref().map(|ssa| rampage_analysis::control::analyze(ssa, &edges)).transpose() {
            Ok(control) => control,
            Err(error) => {
                limitations.push(format!("Control analysis omitted: {error}"));
                None
            }
        };
        let pseudocode = match ssa.as_ref().map(|ssa| rampage_analysis::pseudocode::render(ssa, &edges)).transpose() {
            Ok(pseudocode) => pseudocode,
            Err(error) => {
                limitations.push(format!("Pseudocode omitted: {error}"));
                None
            }
        };
        let structured_control =
            match ssa.as_ref().map(|ssa| rampage_analysis::structure::analyze(ssa, &edges)).transpose() {
                Ok(structure) => structure,
                Err(error) => {
                    limitations.push(format!("Control structuring omitted: {error}"));
                    None
                }
            };
        let structured_pseudocode = if structured_control.is_some() {
            match ssa.as_ref().map(|ssa| rampage_analysis::pseudocode::render_structured(ssa, &edges)).transpose() {
                Ok(output) => output,
                Err(error) => {
                    limitations.push(format!("Structured pseudocode omitted: {error}"));
                    None
                }
            }
        } else {
            None
        };
        Ok(FunctionSummary {
            graph,
            references,
            ir,
            lifted_instructions,
            ssa,
            dataflow,
            pseudocode,
            control,
            structured_control,
            structured_pseudocode,
            type_evidence,
            validated_indirect_targets,
            limitations,
        })
    }
}
