//! How paths leave a function, and which functions never return once tail calls are followed.

use std::collections::{BTreeMap, BTreeSet};

/// How the paths through a function leave it.
#[derive(Debug, Default)]
pub(super) struct Exits {
    /// Some path returns, or leaves through something unknown that may.
    pub returns: bool,
    /// Some path ends in a noreturn call or a trap, or tail-calls a function known never to return.
    pub stops: bool,
    /// Functions some path tail-calls or runs into that were not known never to return.
    pub tail_calls: BTreeSet<u64>,
}

impl Exits {
    /// A path that runs into, or tail-calls, the function at `target`.
    pub fn leave_to(&mut self, target: u64, noreturn: &BTreeSet<u64>) {
        if noreturn.contains(&target) {
            self.stops = true;
        } else {
            self.tail_calls.insert(target);
        }
    }
}

/// The functions among `exits` that never return, given the callees in `noreturn` that never do and the functions
/// in `returns` that must not be inferred.
///
/// A function never returns when no path returns and each path ends in a noreturn call, a trap, or a tail call to
/// (or fall-through into) a function that never returns. Functions that only tail-call each other resolve together:
/// the greatest set closed under that rule is found by dropping, through a worklist over the tail-call graph, every
/// function with a tail call leaving the set. Inference needs evidence, as it does for a single function: some
/// path through the function or the functions it tail-calls must end in a noreturn call or a trap. A cycle of tail
/// calls with no such path is an infinite loop; it never returns either, and Ghidra calls it non-returning, but
/// nothing proves it does not leave through something discovery cannot see, so it is not inferred, and its callers
/// count it as returning.
pub(super) fn never_returning(
    exits: &BTreeMap<u64, &Exits>,
    noreturn: &BTreeSet<u64>,
    returns: &BTreeSet<u64>,
) -> BTreeSet<u64> {
    let mut callers: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (&function, exit) in exits {
        for &target in &exit.tail_calls {
            callers.entry(target).or_default().push(function);
        }
    }
    let callers_of = |function: u64| callers.get(&function).into_iter().flatten().copied();
    let mut set: BTreeSet<u64> = exits
        .iter()
        .filter(|&(function, exit)| !exit.returns && !returns.contains(function))
        .map(|(&function, _)| function)
        .collect();
    loop {
        // Greatest fixpoint: drop every function with a tail call that leaves the set, then its callers in turn.
        let mut dropped: Vec<u64> = set
            .iter()
            .copied()
            .filter(|function| {
                exits[function].tail_calls.iter().any(|target| !set.contains(target) && !noreturn.contains(target))
            })
            .collect();
        while let Some(function) = dropped.pop() {
            if set.remove(&function) {
                dropped.extend(callers_of(function).filter(|caller| set.contains(caller)));
            }
        }
        // Least fixpoint within it: the functions with evidence, and their tail callers.
        let mut evidenced: BTreeSet<u64> = set.iter().copied().filter(|function| exits[function].stops).collect();
        let mut pending: Vec<u64> = evidenced.iter().copied().collect();
        while let Some(function) = pending.pop() {
            for caller in callers_of(function).filter(|caller| set.contains(caller)) {
                if evidenced.insert(caller) {
                    pending.push(caller);
                }
            }
        }
        if evidenced.len() == set.len() {
            return set;
        }
        // Functions without evidence count as returning, which may drop their tail callers.
        set = evidenced;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exits(returns: bool, stops: bool, tail_calls: &[u64]) -> Exits {
        Exits { returns, stops, tail_calls: tail_calls.iter().copied().collect() }
    }

    fn infer(functions: &[(u64, Exits)]) -> Vec<u64> {
        let map = functions.iter().map(|(address, exit)| (*address, exit)).collect();
        never_returning(&map, &BTreeSet::new(), &BTreeSet::new()).into_iter().collect()
    }

    #[test]
    fn functions_that_only_tail_call_each_other_and_abort_never_return() {
        assert_eq!(infer(&[(1, exits(false, false, &[2])), (2, exits(false, true, &[1]))]), [1, 2]);
    }

    #[test]
    fn a_return_anywhere_in_the_cycle_makes_every_member_return() {
        assert!(infer(&[(1, exits(false, true, &[2])), (2, exits(true, true, &[1]))]).is_empty());
    }

    #[test]
    fn a_cycle_with_no_noreturn_call_or_trap_is_not_inferred_nor_are_its_callers() {
        let functions = [(1, exits(false, false, &[2])), (2, exits(false, false, &[1])), (3, exits(false, true, &[1]))];
        assert!(infer(&functions).is_empty());
    }

    #[test]
    fn tail_calls_to_unknown_or_excluded_functions_return() {
        assert!(infer(&[(1, exits(false, true, &[9]))]).is_empty());
        let functions = [(1, exits(false, true, &[2])), (2, exits(false, true, &[]))];
        let map = functions.iter().map(|(address, exit)| (*address, exit)).collect();
        assert!(never_returning(&map, &BTreeSet::new(), &BTreeSet::from([2])).is_empty());
        assert_eq!(never_returning(&map, &BTreeSet::from([9]), &BTreeSet::new()), BTreeSet::from([1, 2]));
    }
}
