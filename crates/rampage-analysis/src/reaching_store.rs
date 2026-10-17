use std::collections::{BTreeMap, BTreeSet};

use crate::{
    dataflow::{self, Known},
    ssa::{Expression, Ssa, Variable},
};

#[derive(Debug, Clone)]
pub(crate) struct Resolution {
    pub value: u64,
    pub stores: BTreeSet<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredValue {
    Constant(u64),
    EntryRegister(u8),
}

#[derive(Debug, Clone)]
struct StoreResolution {
    value: StoredValue,
    stores: BTreeSet<usize>,
}

struct Query<'a> {
    ssa: &'a Ssa,
    values: &'a [Known],
    address: Known,
    bits: u8,
    visiting: BTreeSet<usize>,
    memo: BTreeMap<(usize, usize), Option<StoreResolution>>,
    remaining: &'a mut usize,
    register: Option<u8>,
}

fn interval(address: Known, bits: u8) -> Option<(i128, i128)> {
    let start = match address {
        Known::Constant(value) => i128::from(value),
        Known::Stack(value) => i128::from(value),
        _ => return None,
    };
    let end = start + i128::from(bits / 8);
    if matches!(address, Known::Constant(_)) && end > i128::from(u64::MAX) + 1
        || matches!(address, Known::Stack(_)) && end > i128::from(i64::MAX)
    {
        return None;
    }
    Some((start, end))
}

impl Query<'_> {
    fn resolve(&mut self, id: usize, depth: usize) -> Option<StoreResolution> {
        if depth > 64 || *self.remaining == 0 {
            return None;
        }
        *self.remaining -= 1;
        if let Some(value) = self.memo.get(&(id, depth)) {
            return value.clone();
        }
        if !self.visiting.insert(id) {
            return None;
        }
        let definition = &self.ssa.definitions[id];
        let result = if definition.variable != Variable::Memory {
            None
        } else {
            match &definition.expression {
                Expression::Reference { definition } => self.resolve(*definition, depth + 1),
                Expression::Store { memory, address, value, bits } => {
                    let written = dataflow::evaluate(address, self.values);
                    if written == self.address && *bits == self.bits {
                        let value = if let Some(register) = self.register {
                            dataflow::entry_register(self.ssa, value, self.remaining)
                                .filter(|&source| source == register)
                                .map(StoredValue::EntryRegister)
                        } else if let Known::Constant(value) = dataflow::evaluate(value, self.values) {
                            Some(StoredValue::Constant(value & if *bits == 64 { u64::MAX } else { (1u64 << bits) - 1 }))
                        } else {
                            None
                        };
                        value.map(|value| StoreResolution { value, stores: BTreeSet::from([id]) })
                    } else {
                        let same_domain = matches!(
                            (written, self.address),
                            (Known::Constant(_), Known::Constant(_)) | (Known::Stack(_), Known::Stack(_))
                        );
                        let disjoint = interval(written, *bits)
                            .zip(interval(self.address, self.bits))
                            .is_some_and(|((a, b), (c, d))| b <= c || d <= a);
                        if same_domain && disjoint { self.resolve(*memory, depth + 1) } else { None }
                    }
                }
                Expression::Phi { inputs } if !inputs.is_empty() => {
                    let mut result: Option<StoreResolution> = None;
                    for input in inputs {
                        let Some(resolved) = self.resolve(input.definition, depth + 1) else {
                            result = None;
                            break;
                        };
                        if let Some(existing) = &mut result {
                            if existing.value != resolved.value {
                                result = None;
                                break;
                            }
                            existing.stores.extend(resolved.stores);
                            if existing.stores.len() > 64 {
                                result = None;
                                break;
                            }
                        } else {
                            result = Some(resolved);
                        }
                    }
                    result
                }
                _ => None,
            }
        };
        self.visiting.remove(&id);
        self.memo.insert((id, depth), result.clone());
        result
    }
}

pub(crate) fn resolve(
    ssa: &Ssa,
    values: &[Known],
    memory: usize,
    address: &Expression,
    bits: u8,
    remaining: &mut usize,
) -> Option<Resolution> {
    let address = dataflow::evaluate(address, values);
    interval(address, bits)?;
    let result = Query {
        ssa,
        values,
        address,
        bits,
        visiting: BTreeSet::new(),
        memo: BTreeMap::new(),
        remaining,
        register: None,
    }
    .resolve(memory, 0)?;
    let StoredValue::Constant(value) = result.value else { return None };
    Some(Resolution { value, stores: result.stores })
}

pub(crate) fn resolve_register(
    ssa: &Ssa,
    values: &[Known],
    memory: usize,
    offset: i64,
    register: u8,
    remaining: &mut usize,
) -> Option<BTreeSet<usize>> {
    let address = Known::Stack(offset);
    interval(address, 64)?;
    Query {
        ssa,
        values,
        address,
        bits: 64,
        visiting: BTreeSet::new(),
        memo: BTreeMap::new(),
        remaining,
        register: Some(register),
    }
    .resolve(memory, 0)
    .map(|result| result.stores)
}
