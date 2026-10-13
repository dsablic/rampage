use rampage_analysis::{
    ssa::{self, Expression, InputBlock, Ssa, Variable},
    structure::{self, Region},
};
use rampage_arch::{
    Flow,
    ir::{Effect, LiftedInstruction, Value},
};

struct Execution {
    values: Vec<u64>,
    predecessor: Option<usize>,
    trace: Vec<usize>,
}

impl Execution {
    fn new(ssa: &Ssa, argument: u64) -> Self {
        let values = ssa
            .definitions
            .iter()
            .map(|definition| {
                if matches!(definition.expression, Expression::Input)
                    && definition.variable == (Variable::Register { number: 0 })
                {
                    argument
                } else {
                    0
                }
            })
            .collect();
        Self { values, predecessor: None, trace: vec![] }
    }

    fn expression(&self, expression: &Expression) -> u64 {
        match expression {
            Expression::Reference { definition } => self.values[*definition],
            Expression::Constant { value } => *value,
            Expression::Low32 { value } => self.expression(value) & 0xffff_ffff,
            Expression::Add { left, right } => self.expression(left).wrapping_add(self.expression(right)),
            Expression::Subtract { left, right } => self.expression(left).wrapping_sub(self.expression(right)),
            Expression::Condition { value, nonzero, bit } => {
                let value = self.expression(value);
                let tested = bit.map_or(value, |bit| (value >> bit) & 1);
                u64::from((tested != 0) == *nonzero)
            }
            Expression::Phi { inputs } => {
                self.values[inputs
                    .iter()
                    .find(|input| input.predecessor == self.predecessor)
                    .expect("missing executed phi edge")
                    .definition]
            }
            // Only the switch bound reads flags, and its check is not modelled.
            Expression::Flags { .. } => 0,
            _ => panic!("unsupported test expression: {expression:?}"),
        }
    }

    fn block(&mut self, ssa: &Ssa, index: usize) {
        assert!(self.trace.len() < 100);
        let block = &ssa.blocks[index];
        let phis: Vec<_> =
            block.phis.iter().map(|&id| (id, self.expression(&ssa.definitions[id].expression))).collect();
        for (id, value) in phis {
            self.values[id] = value;
        }
        for statement in &block.statements {
            assert!(!statement.barrier);
            for &id in &statement.definitions {
                self.values[id] = self.expression(&ssa.definitions[id].expression);
            }
        }
        self.predecessor = Some(index);
        self.trace.push(index);
    }

    fn region(&mut self, ssa: &Ssa, region: &Region) {
        match region {
            Region::Sequence { regions } => {
                for region in regions {
                    self.region(ssa, region);
                }
            }
            Region::Block { block } => self.block(ssa, *block),
            Region::If { condition, taken, not_taken } => {
                self.region(ssa, if self.expression(condition) != 0 { taken } else { not_taken });
            }
            Region::Loop { header, condition, body_when_true, body } => loop {
                self.block(ssa, *header);
                if (self.expression(condition) != 0) != *body_when_true {
                    break;
                }
                self.region(ssa, body);
            },
            Region::Switch { index, cases, .. } => {
                let value = self.expression(index.as_ref().expect("recovered index"));
                let case = cases.iter().find(|case| case.values.contains(&value)).expect("value has a case");
                self.region(ssa, &case.body);
            }
        }
    }

    /// `table` gives the block each switch index dispatches to, for a graph with one switch on register 0.
    fn graph_with_table(&mut self, ssa: &Ssa, edges: &[(usize, usize)], table: &[usize], index: &Expression) {
        let mut at = ssa.entry;
        loop {
            self.block(ssa, at);
            let statement = ssa.blocks[at].statements.last().unwrap();
            at = match statement.flow {
                Flow::Return => break,
                Flow::IndirectJump => table[self.expression(index) as usize],
                _ => edges.iter().find(|&&(from, _)| from == at).unwrap().1,
            };
        }
    }

    fn graph(&mut self, ssa: &Ssa, edges: &[(usize, usize)]) {
        let mut index = ssa.entry;
        loop {
            self.block(ssa, index);
            let statement = ssa.blocks[index].statements.last().unwrap();
            if statement.flow == Flow::Return {
                break;
            }
            let next: Vec<_> = edges.iter().filter(|&&(from, _)| from == index).map(|&(_, to)| to).collect();
            index = if let Flow::ConditionalJump(target) = statement.flow {
                let condition = statement
                    .observations
                    .iter()
                    .find(|expression| matches!(expression, Expression::Condition { .. }))
                    .unwrap();
                let taken = self.expression(condition) != 0;
                *next.iter().find(|&&to| (ssa.blocks[to].address == target) == taken).unwrap()
            } else {
                next[0]
            };
        }
    }
}

fn instruction(address: u64, flow: Flow, effect: Effect) -> InputBlock {
    InputBlock {
        address,
        instructions: vec![LiftedInstruction { address, bits: 64, flow, complete: true, effects: vec![effect] }],
    }
}

#[test]
fn structured_diamond_preserves_both_executed_phi_edges() {
    let input = [
        instruction(
            0,
            Flow::ConditionalJump(8),
            Effect::ConditionalControl { value: Value::Register { number: 0 }, nonzero: false, bit: None },
        ),
        instruction(
            4,
            Flow::Jump(12),
            Effect::Assign { destination: Value::Register { number: 1 }, value: Value::Constant { value: 7 } },
        ),
        instruction(
            8,
            Flow::Next,
            Effect::Assign { destination: Value::Register { number: 1 }, value: Value::Constant { value: 11 } },
        ),
        instruction(
            12,
            Flow::Return,
            Effect::Assign { destination: Value::Register { number: 0 }, value: Value::Register { number: 1 } },
        ),
    ];
    let edges = [(0, 1), (0, 2), (1, 3), (2, 3)];
    let ssa = ssa::build(&input, &edges, 0).unwrap();
    let structure = structure::analyze(&ssa, &edges).unwrap();
    for (argument, expected) in [(0, 11), (1, 7)] {
        let mut graph = Execution::new(&ssa, argument);
        graph.graph(&ssa, &edges);
        let mut structured = Execution::new(&ssa, argument);
        structured.region(&ssa, &structure.body);
        assert_eq!(graph.trace, structured.trace);
        let result = ssa.blocks[3].statements[0].definitions[0];
        assert_eq!(structured.values[result], expected);
    }
}

#[test]
fn structured_loop_phi_values_match_cfg_execution_on_every_iteration() {
    let mut input = [
        instruction(0, Flow::Next, Effect::Control { inputs: vec![] }),
        instruction(
            4,
            Flow::ConditionalJump(12),
            Effect::ConditionalControl { value: Value::Register { number: 0 }, nonzero: false, bit: None },
        ),
        instruction(
            8,
            Flow::Jump(4),
            Effect::Assign {
                destination: Value::Register { number: 0 },
                value: Value::Subtract {
                    left: Box::new(Value::Register { number: 0 }),
                    right: Box::new(Value::Constant { value: 1 }),
                },
            },
        ),
        instruction(12, Flow::Return, Effect::Control { inputs: vec![Value::Register { number: 0 }] }),
    ];
    let edges = [(0, 1), (1, 2), (1, 3), (2, 1)];
    for body_when_true in [false, true] {
        input[1].instructions[0].flow = Flow::ConditionalJump(if body_when_true { 8 } else { 12 });
        input[1].instructions[0].effects = vec![Effect::ConditionalControl {
            value: Value::Register { number: 0 },
            nonzero: body_when_true,
            bit: None,
        }];
        let ssa = ssa::build(&input, &edges, 0).unwrap();
        let structure = structure::analyze(&ssa, &edges).unwrap();
        for argument in 0..10 {
            let mut graph = Execution::new(&ssa, argument);
            graph.graph(&ssa, &edges);
            let mut structured = Execution::new(&ssa, argument);
            structured.region(&ssa, &structure.body);
            assert_eq!(graph.trace, structured.trace);
            assert_eq!(graph.values, structured.values);
            assert_eq!(structured.trace.iter().filter(|&&block| block == 2).count(), argument as usize);
        }
    }
}

#[test]
fn structured_switch_phi_values_match_cfg_execution_for_every_index() {
    let assign =
        |value| Effect::Assign { destination: Value::Register { number: 1 }, value: Value::Constant { value } };
    let compare = Effect::SetFlags {
        operation: rampage_arch::ir::FlagOperation::Subtract,
        left: Value::Register { number: 0 },
        right: Value::Constant { value: 3 },
    };
    // 0: cmp x0, #3; 4: br x9 through entries [0x20, 0x30, 0x50, 0x20]; 0x50 joins with a phi of x1.
    let mut dispatch = instruction(0, Flow::Next, compare);
    dispatch.instructions.extend(
        instruction(4, Flow::IndirectJump, Effect::IndirectBranch { target: Value::Register { number: 9 } })
            .instructions,
    );
    let input = [
        dispatch,
        instruction(0x20, Flow::Jump(0x50), assign(7)),
        instruction(0x30, Flow::Jump(0x50), assign(11)),
        instruction(0x50, Flow::Return, Effect::Control { inputs: vec![Value::Register { number: 1 }] }),
    ];
    let edges = [(0, 1), (0, 2), (0, 3), (1, 3), (2, 3)];
    let ssa = ssa::build(&input, &edges, 0).unwrap();
    let switch = rampage_analysis::discover::Switch {
        jump: 4,
        cases: vec![0x20, 0x30, 0x50],
        table: vec![0x20, 0x30, 0x50, 0x20],
        guard: 0,
    };
    let structure = structure::analyze_with_switches(&ssa, &edges, &[switch]).unwrap();
    let Region::Sequence { regions } = &structure.body else { panic!("not sequence") };
    let Region::Switch { index: Some(index), .. } = &regions[1] else { panic!("no switch: {regions:?}") };
    for argument in 0..4 {
        let mut graph = Execution::new(&ssa, argument);
        graph.graph_with_table(&ssa, &edges, &[1, 2, 3, 1], index);
        let mut structured = Execution::new(&ssa, argument);
        structured.region(&ssa, &structure.body);
        assert_eq!(graph.trace, structured.trace);
        assert_eq!(graph.values, structured.values);
    }
}
