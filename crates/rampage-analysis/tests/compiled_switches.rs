use std::path::PathBuf;

use rampage_analysis::{
    discover::{self, DiscoveredFunction, Program, XrefKind},
    functions,
    memory::Memory,
    pseudocode,
    ssa::{self, Expression, InputBlock, Ssa, Variable},
    structure::{self, Region, SwitchCase},
};
use rampage_arch::ir::{self, Effect, FlagOperation, Value};
use rampage_arch::{Arch, Flow, JumpTable};
use rampage_loaders::Binary;

// Return tags identify the source cases independently of compiler layout or recovered table order.
const CASE_RETURNS: [u64; 8] = [11, 23, 37, 53, 71, 89, 107, 131];

fn open(name: &str) -> Binary {
    Binary::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)).unwrap()
}

fn return_tag(binary: &Binary, start: u64) -> u64 {
    let mut decoder = binary.decoder().unwrap();
    let mut at = start;
    let mut result = None;
    for _ in 0..64 {
        let bytes = binary.code_from(at).unwrap();
        let instruction = decoder.decode(bytes, at);
        assert!(instruction.len > 0);
        match binary.arch {
            Arch::X86 if bytes[0] == 0xb8 && instruction.len == 5 => {
                result = Some(u64::from(u32::from_le_bytes(bytes[1..5].try_into().unwrap())));
            }
            Arch::Aarch64 => {
                for effect in ir::lift(binary.arch, bytes, &instruction).effects {
                    if let Effect::Assign {
                        destination: Value::Register { number: 0 },
                        value: Value::Constant { value },
                    } = effect
                    {
                        result = Some(value);
                    }
                }
            }
            Arch::X86 => {}
            arch => panic!("unexpected fixture architecture {arch}"),
        }
        match instruction.flow {
            Flow::Return => return result.expect("case writes its return tag"),
            Flow::Jump(target) => at = target,
            Flow::Next => at += u64::from(instruction.len),
            flow => panic!("case unexpectedly transfers at {at:#x}: {flow:?}"),
        }
    }
    panic!("case did not return within the fixture budget")
}

fn assert_discovery(binary: &Binary, program: &Program, function: &DiscoveredFunction, inverse: bool) -> u64 {
    assert_eq!(function.switches.len(), 1, "{function:?}");
    let switch = &function.switches[0];
    assert_eq!(switch.table.len(), CASE_RETURNS.len());
    assert_eq!(switch.cases.len(), CASE_RETURNS.len());
    assert!(function.blocks.len() <= 12 && function.instruction_count <= 100, "{function:?}");
    assert!(function.contains(switch.guard));
    assert!(function.contains(switch.jump));
    let symbol = binary.symbol_by_name("switch_pic").unwrap();
    for (&target, expected) in switch.table.iter().zip(CASE_RETURNS) {
        assert!((symbol.address..symbol.address + symbol.size).contains(&target));
        assert!(
            function.contains(target),
            "case {target:#x} escaped the source function: {function:?}; function entries: {:?}",
            program.functions.iter().map(|function| function.address).collect::<Vec<_>>()
        );
        assert_eq!(return_tag(binary, target), expected, "table entry selects the wrong source case");
        assert!(
            program
                .xrefs
                .iter()
                .any(|xref| { xref.from == switch.jump && xref.to == target && xref.kind == XrefKind::Jump })
        );
    }
    let dispatch_edges: Vec<_> =
        program.xrefs.iter().filter(|xref| xref.from == switch.jump && xref.kind == XrefKind::Jump).collect();
    assert_eq!(dispatch_edges.len(), CASE_RETURNS.len(), "{dispatch_edges:?}");
    let mut decoder = binary.decoder().unwrap();
    assert_eq!(decoder.decode(binary.code_from(switch.jump).unwrap(), switch.jump).flow, Flow::IndirectJump);
    let guard_block = function.blocks.iter().find(|block| (block.start..block.end).contains(&switch.guard)).unwrap();
    let mut at = switch.guard;
    while at < guard_block.end {
        let instruction = decoder.decode(binary.code_from(at).unwrap(), at);
        if let Flow::ConditionalJump(target) = instruction.flow {
            let fall_through = at + u64::from(instruction.len);
            let (bounded, default) = if inverse { (target, fall_through) } else { (fall_through, target) };
            assert!(
                function
                    .blocks
                    .iter()
                    .any(|block| { block.start == bounded && (block.start..block.end).contains(&switch.jump) })
            );
            assert!(function.contains(default));
            assert!(!switch.cases.contains(&default));
            assert_eq!(return_tag(binary, default), 149);
            return default;
        }
        assert!(instruction.len > 0);
        at += u64::from(instruction.len);
    }
    panic!("no bounding branch after recovered guard")
}

#[test]
fn compiled_pic_i386_retains_the_bounded_switch_and_case_order() {
    let binary = open("switch-pic-i386.so");
    assert_eq!(binary.arch, Arch::X86);
    let symbol = binary.symbol_by_name("switch_pic").unwrap();
    let program = functions::analyze(&binary).unwrap();
    let function = program.function_at(symbol.address).unwrap();
    assert_discovery(&binary, &program, function, false);
    let switch = &function.switches[0];
    let table = dispatch_evidence(&binary, function, false);
    assert_eq!(table.guard, switch.guard);
    assert_eq!(table.entries, CASE_RETURNS.len() as u64);
    assert_eq!(table.entry_size, 4);
    assert!(table.base.is_some() && table.signed, "GOT-relative i386 entries need signed offsets: {table:?}");
    for (index, &target) in switch.table.iter().enumerate() {
        let raw = binary.read_constant(table.slot(index as u64).unwrap(), table.entry_size).unwrap();
        assert_eq!(table.target(raw), Some(target));
    }
}

fn dispatch_evidence(binary: &Binary, function: &DiscoveredFunction, inverse: bool) -> JumpTable {
    let switch = &function.switches[0];
    let mut decoder = binary.decoder().unwrap();
    let read = |address, size| binary.read_constant(address, size);
    let mut at = function.address;
    for _ in 0..100 {
        let instruction = decoder.decode_with_memory(binary.code_from(at).unwrap(), at, &read);
        if at == switch.jump {
            return decoder.jump_table().expect("dispatch has bounded table evidence");
        }
        assert!(instruction.len > 0 && at < switch.jump);
        if inverse && let Flow::ConditionalJump(target) = instruction.flow {
            let taken = decoder.taken_facts().unwrap();
            decoder.assume(&taken);
            at = target;
        } else {
            at += u64::from(instruction.len);
        }
    }
    panic!("dispatch not reached within fixture budget")
}

fn lifted_graph(binary: &Binary, function: &DiscoveredFunction) -> (Ssa, Vec<(usize, usize)>) {
    let mut decoder = binary.decoder().unwrap();
    let blocks: Vec<_> = function
        .blocks
        .iter()
        .map(|block| {
            decoder.reset();
            let mut at = block.start;
            let mut instructions = Vec::new();
            while at < block.end {
                let bytes = binary.code_from(at).unwrap();
                let instruction = decoder.decode(bytes, at);
                assert!(instruction.len > 0);
                let lifted = ir::lift(binary.arch, bytes, &instruction);
                assert!(lifted.complete, "incomplete lift at {at:#x}: {lifted:?}");
                instructions.push(lifted);
                at += u64::from(instruction.len);
            }
            assert_eq!(at, block.end);
            InputBlock { address: block.start, instructions }
        })
        .collect();
    let block_at = |address| blocks.iter().position(|block| block.address == address).unwrap();
    let mut edges = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let last = block.instructions.last().unwrap();
        match last.flow {
            Flow::ConditionalJump(target) => {
                edges.push((index, block_at(target)));
                edges.push((index, block_at(function.blocks[index].end)));
            }
            Flow::Jump(target) => edges.push((index, block_at(target))),
            Flow::IndirectJump => {
                let switch = function.switches.iter().find(|switch| switch.jump == last.address).unwrap();
                edges.extend(switch.cases.iter().map(|&target| (index, block_at(target))));
            }
            Flow::Return => {}
            flow => panic!("unexpected fixture block terminator {flow:?}"),
        }
    }
    let entry = block_at(function.address);
    (ssa::build(&blocks, &edges, entry).unwrap(), edges)
}

fn switch_region(region: &Region) -> Option<(usize, &Expression, &[SwitchCase])> {
    match region {
        Region::Sequence { regions } => regions.iter().find_map(switch_region),
        Region::If { taken, not_taken, .. } => switch_region(taken).or_else(|| switch_region(not_taken)),
        Region::Switch { dispatch, index: Some(index), cases } => Some((*dispatch, index, cases)),
        _ => None,
    }
}

fn index_value(ssa: &Ssa, expression: &Expression, selector: u64, budget: usize) -> u64 {
    assert!(budget > 0, "unbounded recovered index");
    match expression {
        Expression::Low32 { value } => index_value(ssa, value, selector, budget - 1) & 0xffff_ffff,
        Expression::Reference { definition } => {
            let definition = &ssa.definitions[*definition];
            if definition.variable == (Variable::Register { number: 0 })
                && matches!(definition.expression, Expression::Input)
            {
                selector
            } else {
                index_value(ssa, &definition.expression, selector, budget - 1)
            }
        }
        Expression::Phi { inputs } if inputs.len() == 1 => {
            index_value(ssa, &Expression::Reference { definition: inputs[0].definition }, selector, budget - 1)
        }
        expression => panic!("index is not the original selector: {expression:?}"),
    }
}

fn first_block(region: &Region) -> Option<usize> {
    match region {
        Region::Block { block } => Some(*block),
        Region::Sequence { regions } => regions.iter().find_map(first_block),
        _ => None,
    }
}

fn route_value(ssa: &Ssa, expression: &Expression, selector: u64, budget: usize) -> Result<u64, String> {
    if budget == 0 {
        return Err("routing expression budget exceeded".to_owned());
    }
    let value = |expression| route_value(ssa, expression, selector, budget - 1);
    match expression {
        Expression::Constant { value } => Ok(*value),
        Expression::Low32 { value: input } => Ok(value(input)? & 0xffff_ffff),
        Expression::Reference { definition } => {
            let definition = &ssa.definitions[*definition];
            if definition.variable == (Variable::Register { number: 0 })
                && matches!(definition.expression, Expression::Input)
            {
                Ok(selector)
            } else {
                value(&definition.expression)
            }
        }
        Expression::Phi { inputs } if inputs.len() == 1 => {
            value(&Expression::Reference { definition: inputs[0].definition })
        }
        Expression::FlagsCondition { flags, condition } => {
            let Expression::Flags { operation: FlagOperation::Subtract, left, right, bits } =
                &ssa.definitions[*flags].expression
            else {
                return Err("routing guard is not a comparison".to_owned());
            };
            let mask = match bits {
                32 => u64::from(u32::MAX),
                64 => u64::MAX,
                _ => return Err("unsupported routing comparison width".to_owned()),
            };
            let (left, right) = (value(left)? & mask, value(right)? & mask);
            let taken = match condition {
                2 => left >= right,
                3 => left < right,
                8 => left > right,
                9 => left <= right,
                _ => return Err("routing guard is not unsigned".to_owned()),
            };
            Ok(u64::from(taken))
        }
        expression => Err(format!("unsupported routing expression: {expression:?}")),
    }
}

struct StructuredRoute<'a> {
    binary: &'a Binary,
    ssa: &'a Ssa,
    selector: u64,
    remaining: usize,
}

impl StructuredRoute<'_> {
    fn walk(&mut self, region: &Region) -> Result<Option<u64>, String> {
        self.remaining = self.remaining.checked_sub(1).ok_or("structured routing budget exceeded")?;
        match region {
            Region::Sequence { regions } => {
                for region in regions {
                    if let Some(tag) = self.walk(region)? {
                        return Ok(Some(tag));
                    }
                }
                Ok(None)
            }
            Region::Block { block } => {
                let block = &self.ssa.blocks[*block];
                if block.statements.last().is_some_and(|statement| statement.flow == Flow::Return) {
                    Ok(Some(return_tag(self.binary, block.address)))
                } else {
                    Ok(None)
                }
            }
            Region::If { condition, taken, not_taken } => {
                let taken_edge = route_value(self.ssa, condition, self.selector, 16)? != 0;
                self.walk(if taken_edge { taken } else { not_taken })
            }
            Region::Switch { index: Some(index), cases, .. } => {
                let value = route_value(self.ssa, index, self.selector, 16)?;
                let case = cases
                    .iter()
                    .find(|case| case.values.contains(&value))
                    .ok_or_else(|| format!("out-of-range selector {value} reached structured dispatch"))?;
                self.walk(&case.body)
            }
            _ => Err("unexpected region in compiler fixture route".to_owned()),
        }
    }
}

fn structured_tag(binary: &Binary, ssa: &Ssa, region: &Region, selector: u64) -> Result<u64, String> {
    StructuredRoute { binary, ssa, selector, remaining: 64 }
        .walk(region)?
        .ok_or_else(|| "structured route did not reach a return".to_owned())
}

fn assert_arm64(name: &str, inverse: bool) {
    let binary = open(name);
    assert_eq!(binary.arch, Arch::Aarch64);
    let symbol = binary.symbol_by_name("switch_pic").unwrap();
    let program = functions::analyze(&binary).unwrap();
    let function = program.function_at(symbol.address).unwrap();
    let default = assert_discovery(&binary, &program, function, inverse);
    let switch = &function.switches[0];
    let (ssa, edges) = lifted_graph(&binary, function);
    let guard_block = ssa
        .blocks
        .iter()
        .find(|block| block.statements.iter().any(|statement| statement.address == switch.guard))
        .unwrap();
    let branch = guard_block.statements.last().unwrap();
    let expected_condition = if inverse { 9 } else { 8 };
    assert!(branch.observations.iter().any(|observation| {
        matches!(observation, Expression::FlagsCondition { condition, .. } if *condition == expected_condition)
    }));
    if !inverse {
        assert!(branch.address > switch.guard + 4, "fixture no longer has compiler-scheduled guard separation");
        let guard_position =
            guard_block.statements.iter().position(|statement| statement.address == switch.guard).unwrap();
        let scheduled = &guard_block.statements[guard_position + 1..guard_block.statements.len() - 1];
        assert!(
            scheduled
                .iter()
                .flat_map(|statement| &statement.definitions)
                .any(|&definition| { matches!(ssa.definitions[definition].expression, Expression::Store { .. }) }),
            "compiler fixture must retain the scheduled volatile store"
        );
    }
    let structure = structure::analyze_with_switches(&ssa, &edges, &function.switches).unwrap();
    let (dispatch, index, cases) = switch_region(&structure.body).expect("structured switch with recovered index");
    assert_eq!(ssa.blocks[dispatch].statements.last().unwrap().address, switch.jump);
    assert_eq!(cases.len(), CASE_RETURNS.len());
    for (value, (case, &target)) in cases.iter().zip(&switch.table).enumerate() {
        assert_eq!(case.values, [value as u64]);
        assert_eq!(ssa.blocks[first_block(&case.body).unwrap()].address, target);
        assert_eq!(index_value(&ssa, index, value as u64, 16), value as u64);
    }
    assert_eq!(index_value(&ssa, index, 0x1_0000_0005, 16), 5);
    assert_eq!(index_value(&ssa, index, u64::from(u32::MAX), 16), u64::from(u32::MAX));
    let flat = pseudocode::render_with_switches(&ssa, &edges, &function.switches).unwrap();
    let default_block = ssa.blocks.iter().position(|block| block.address == default).unwrap();
    assert!(flat.text.contains(&format!("default: goto bb{default_block};")), "{}", flat.text);
    assert!(!flat.text.contains("unknown_target"), "{}", flat.text);
    assert!(ssa.definitions.len() <= 512 && edges.len() <= 32);
    for (selector, expected) in (0u64..).zip(CASE_RETURNS).chain([(8, 149), (u64::from(u32::MAX), 149)]) {
        assert_eq!(structured_tag(&binary, &ssa, &structure.body, selector), Ok(expected), "{name}: {selector}");
    }
}

#[test]
fn compiled_arm64_inverse_guard_retains_index_cases_and_default() {
    assert_arm64("switch-inverse-arm64.so", true);
}

#[test]
fn compiled_arm64_scheduled_guard_retains_index_cases_and_default() {
    assert_arm64("switch-scheduled-arm64.so", false);
}

fn swap_guard_arms(region: &mut Region) -> bool {
    match region {
        Region::Sequence { regions } => regions.iter_mut().any(swap_guard_arms),
        Region::If { taken, not_taken, .. } => {
            std::mem::swap(taken, not_taken);
            true
        }
        _ => false,
    }
}

fn assert_swapped_compiled_guard_arms_rejected(name: &str, inverse: bool) {
    let binary = open(name);
    let program = functions::analyze(&binary).unwrap();
    let function = program.function_at(binary.symbol_by_name("switch_pic").unwrap().address).unwrap();
    assert_discovery(&binary, &program, function, inverse);
    let (ssa, edges) = lifted_graph(&binary, function);
    let mut structure = structure::analyze_with_switches(&ssa, &edges, &function.switches).unwrap();
    let selectors = [(7, CASE_RETURNS[7]), (8, 149), (u64::from(u32::MAX), 149)];
    for (selector, expected) in selectors {
        assert_eq!(structured_tag(&binary, &ssa, &structure.body, selector), Ok(expected));
    }
    assert!(swap_guard_arms(&mut structure.body));
    for (selector, expected) in selectors {
        assert_ne!(structured_tag(&binary, &ssa, &structure.body, selector), Ok(expected), "{name}: {selector}");
    }
}

#[test]
fn structured_routing_oracle_rejects_swapped_compiled_inverse_guard_arms() {
    assert_swapped_compiled_guard_arms_rejected("switch-inverse-arm64.so", true);
}

#[test]
fn structured_routing_oracle_rejects_swapped_compiled_scheduled_guard_arms() {
    assert_swapped_compiled_guard_arms_rejected("switch-scheduled-arm64.so", false);
}

// These views deliberately mutate compiled bytes/evidence; they are not additional compiler-generated fixtures.
#[derive(Clone)]
struct MutatedImage<'a> {
    binary: &'a Binary,
    base: u64,
    code: Vec<u8>,
    constant: Option<(u64, u8, u64)>,
}

impl<'a> MutatedImage<'a> {
    fn new(binary: &'a Binary, function: &DiscoveredFunction) -> Self {
        Self {
            binary,
            base: function.address,
            code: binary.code_from(function.address).unwrap().to_vec(),
            constant: None,
        }
    }

    fn patched_constant(&self, address: u64, size: u8) -> Option<u64> {
        self.constant.and_then(|(slot, width, value)| (slot == address && width == size).then_some(value))
    }
}

impl Memory for MutatedImage<'_> {
    fn code_from(&self, address: u64) -> Option<&[u8]> {
        let offset = address.checked_sub(self.base).and_then(|offset| usize::try_from(offset).ok());
        offset
            .and_then(|offset| self.code.get(offset..))
            .filter(|bytes| !bytes.is_empty())
            .or_else(|| self.binary.code_from(address))
    }

    fn is_mapped(&self, address: u64) -> bool {
        Memory::is_mapped(self.binary, address)
    }

    fn is_executable(&self, address: u64) -> bool {
        Memory::is_executable(self.binary, address)
    }

    fn immediates_may_be_addresses(&self) -> bool {
        Memory::immediates_may_be_addresses(self.binary)
    }

    fn read_pointer(&self, address: u64, size: u8) -> Option<u64> {
        self.patched_constant(address, size).or_else(|| self.binary.read_pointer(address, size))
    }

    fn read_constant(&self, address: u64, size: u8) -> Option<u64> {
        self.patched_constant(address, size).or_else(|| self.binary.read_constant(address, size))
    }
}

fn assert_mutation_baseline(image: &MutatedImage<'_>, original: &DiscoveredFunction) {
    let program = discover::discover(image, || image.binary.decoder().unwrap(), &[original.address]);
    assert_eq!(program.function_at(original.address).unwrap().switches, original.switches);
}

fn assert_mutation_rejects_switch(image: &MutatedImage<'_>, original: &DiscoveredFunction) {
    let program = discover::discover(image, || image.binary.decoder().unwrap(), &[original.address]);
    let function = program.function_at(original.address).unwrap();
    assert!(function.switches.is_empty(), "mutated compiler input retained stale switch: {function:?}");
    assert!(function.blocks.len() <= 12 && function.instruction_count <= 100);
    let switch = &original.switches[0];
    assert!(!program.xrefs.iter().any(|xref| xref.kind == XrefKind::Jump && xref.from == switch.jump));
    assert!(switch.cases.iter().all(|&target| !function.contains(target)), "partial case recovery: {function:?}");
}

fn assert_invalid_compiled_table_target(name: &str, inverse: bool) {
    let binary = open(name);
    let program = functions::analyze(&binary).unwrap();
    let function = program.function_at(binary.symbol_by_name("switch_pic").unwrap().address).unwrap();
    assert_discovery(&binary, &program, function, inverse);
    let table = dispatch_evidence(&binary, function, inverse);
    let raw = u64::MAX >> (64 - u32::from(table.entry_size) * 8);
    let invalid_target = table.target(raw).unwrap();
    assert!(binary.code_from(invalid_target).is_none(), "mutation must actually select non-code");
    let mut image = MutatedImage::new(&binary, function);
    assert_mutation_baseline(&image, function);
    image.constant = Some((table.slot(table.entries - 1).unwrap(), table.entry_size, raw));
    assert_mutation_rejects_switch(&image, function);
}

#[test]
fn mutated_compiled_pic_i386_table_with_an_invalid_last_target_leaves_no_partial_switch_evidence() {
    assert_invalid_compiled_table_target("switch-pic-i386.so", false);
}

#[test]
fn mutated_compiled_inverse_arm64_table_with_an_invalid_last_target_leaves_no_partial_switch_evidence() {
    assert_invalid_compiled_table_target("switch-inverse-arm64.so", true);
}

#[test]
fn mutated_compiled_scheduled_arm64_table_with_an_invalid_last_target_leaves_no_partial_switch_evidence() {
    assert_invalid_compiled_table_target("switch-scheduled-arm64.so", false);
}

#[test]
fn mutated_compiled_scheduled_guards_reject_index_and_flag_clobbers() {
    let binary = open("switch-scheduled-arm64.so");
    let program = functions::analyze(&binary).unwrap();
    let function = program.function_at(binary.symbol_by_name("switch_pic").unwrap().address).unwrap();
    assert_discovery(&binary, &program, function, false);
    let guard = function.switches[0].guard;
    let baseline = MutatedImage::new(&binary, function);
    assert_mutation_baseline(&baseline, function);
    // Replace the compiler's scheduled add after cmp with add w0, w0, #1 or cmp w1, #7.
    for clobber in [0x1100_0400u32, 0x7100_1c3f] {
        let mut image = baseline.clone();
        let offset = usize::try_from(guard + 4 - image.base).unwrap();
        image.code[offset..offset + 4].copy_from_slice(&clobber.to_le_bytes());
        assert_mutation_rejects_switch(&image, function);
    }
}
