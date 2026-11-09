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
        self.summary_from_graph(self.function_graph(address)?)
    }

    pub(crate) fn function_summary_for_frame(&self, address: u64) -> Result<FunctionSummary, ApiError> {
        self.summary_from_graph(self.function_graph_for_frame(address)?)
    }

    fn summary_from_graph(&self, graph: FunctionGraph) -> Result<FunctionSummary, ApiError> {
        let references = self.xrefs(XrefQuery::From(graph.address), None, Some(1000))?;
        let mut ir = Vec::new();
        let sleigh = crate::decoder::sleigh_raw(&self.binary);
        for line in graph.blocks.iter().flat_map(|block| &block.lines) {
            if sleigh {
                continue;
            }
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
                accesses: line.accesses,
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
        let gates =
            graph.blocks.iter().flat_map(|block| &block.lines).filter(|line| line.decode_gate.is_some()).count();
        if sleigh {
            limitations.push(
                "Selected Sleigh Project profiles have structural flow only; native IR/SSA is unavailable.".into(),
            );
        }
        if gates != 0 {
            limitations.push(format!(
                "{gates} valid instructions have unknown successor flow; \
                 retained gates forbid successor and noreturn inference."
            ));
        }
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
                    let program = &self.analysis()?.program;
                    for statement in ssa.blocks.iter_mut().flat_map(|block| &mut block.statements) {
                        statement.noreturn = program.is_noreturn_call(statement.address);
                    }
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
        let mut validated_indirect_targets = Vec::new();
        if let Some(data) = &dataflow {
            let mut decoder = crate::decoder::project_decoder(self)?;
            for evidence in &data.indirect_targets {
                if evidence.target == 0
                    || evidence.target % 4 != 0
                    || !self.binary.is_code(evidence.target)
                    || self
                        .binary
                        .segment_containing(evidence.target)
                        .is_none_or(|segment| !segment.perms.execute || !segment.perms.read)
                {
                    continue;
                }
                let Some(bytes) = self.binary.code_from(evidence.target).and_then(|bytes| bytes.get(..4)) else {
                    continue;
                };
                decoder.begin_run();
                let instruction = decoder.decode(bytes, evidence.target);
                let gate = decoder.decode_gate();
                if gate.is_some() || instruction.flow == rampage_arch::Flow::Invalid {
                    continue;
                }
                validated_indirect_targets.push(rampage_analysis::dataflow::IndirectTarget {
                    address: evidence.address,
                    target: evidence.target,
                    call: evidence.call,
                    input_definitions: evidence.input_definitions.clone(),
                });
            }
        }
        let edges: Vec<_> = graph.edges.iter().map(|edge| (edge.from, edge.to)).collect();
        let control = match ssa.as_ref().map(|ssa| rampage_analysis::control::analyze(ssa, &edges)).transpose() {
            Ok(control) => control,
            Err(error) => {
                limitations.push(format!("Control analysis omitted: {error}"));
                None
            }
        };
        let switches =
            self.analysis()?.program.function_at(graph.address).map_or(&[][..], |function| &function.switches);
        let pseudocode = match ssa
            .as_ref()
            .map(|ssa| rampage_analysis::pseudocode::render_with_switches(ssa, &edges, switches))
            .transpose()
        {
            Ok(pseudocode) => pseudocode,
            Err(error) => {
                limitations.push(format!("Pseudocode omitted: {error}"));
                None
            }
        };
        let structured_control = match ssa
            .as_ref()
            .map(|ssa| rampage_analysis::structure::analyze_with_switches(ssa, &edges, switches))
            .transpose()
        {
            Ok(structure) => structure,
            Err(error) => {
                limitations.push(format!("Control structuring omitted: {error}"));
                None
            }
        };
        let structured_pseudocode = if structured_control.is_some() {
            match ssa
                .as_ref()
                .map(|ssa| rampage_analysis::pseudocode::render_structured_with_switches(ssa, &edges, switches))
                .transpose()
            {
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
