//! Claims about data and protection: `region` (a checksum or digest covers a byte range), `lock` (a lock mechanism
//! decides in or guards a function) and `layout` (a type's member at an offset).

use serde::Deserialize;
use serde_json::{Value, json};

use super::reference::{AlgorithmSpec, Reference, Shape};
use super::{Address, Confidence, Outcome, address, function_start, hex};
use crate::{IntegrityRequest, LockQuery, Project};

/// Bytes a region claim recomputes.
const MAX_REGION_BYTES: u64 = 64 << 20;
/// Checks and mechanisms an unknown answer lists.
const SHOWN: usize = 4;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegionClaim {
    start: Address,
    /// Exclusive.
    end: Address,
    algorithm: Option<AlgorithmSpec>,
    /// Where the value is stored: then the claim is recomputed exactly.
    stored: Option<Address>,
    /// `little` or `big` for the stored value (default the image's byte order).
    endian: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockClaim {
    function: Address,
    category: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayoutClaim {
    #[serde(rename = "type")]
    type_name: String,
    /// A member name, or a dotted path (DWARF and Go).
    member: String,
    offset: Option<Address>,
    size: Option<u64>,
}

/// The image bytes of `[start, end)`, across adjacent segments; `None` when part of it has no file bytes.
fn read_range(project: &Project, start: u64, end: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity((end - start) as usize);
    let mut at = start;
    while at < end {
        let chunk = project.binary.read_to_segment_end(at)?;
        let take = chunk.len().min((end - at) as usize);
        bytes.extend_from_slice(&chunk[..take]);
        at += take as u64;
    }
    Some(bytes)
}

pub(crate) fn region(project: &std::sync::Arc<Project>, claim: &RegionClaim) -> Outcome {
    let (start, end) = match (claim.start.resolve(project), claim.end.resolve(project)) {
        (Ok(start), Ok(end)) => (start, end),
        (Err(error), _) | (_, Err(error)) => return error.into(),
    };
    if start >= end || end - start > MAX_REGION_BYTES {
        return Outcome::invalid(format!("a region is start < end, at most {MAX_REGION_BYTES} bytes"));
    }
    let reference = match claim.algorithm.as_ref().map(Reference::parse).transpose() {
        Ok(reference) => reference,
        Err(error) => return Outcome::invalid(error),
    };
    match (&claim.stored, reference) {
        (Some(stored), Some(reference)) => {
            let stored = match stored.resolve(project) {
                Ok(stored) => stored,
                Err(error) => return error.into(),
            };
            recompute(project, start, end, stored, &reference, claim.endian.as_deref())
        }
        (Some(_), None) => Outcome::invalid("a stored value is recomputed with an algorithm: name it"),
        (None, reference) => detected(project, start, end, reference.as_ref()),
    }
}

fn recompute(
    project: &Project,
    start: u64,
    end: u64,
    stored: u64,
    reference: &Reference,
    endian: Option<&str>,
) -> Outcome {
    let big_endian = match endian {
        None => project.binary.big_endian,
        Some("big") => true,
        Some("little") => false,
        Some(other) => return Outcome::invalid(format!("endian {other:?} is little or big")),
    };
    let Some(data) = read_range(project, start, end) else {
        return Outcome::invalid(format!("[{start:#x}, {end:#x}) is not wholly backed by image bytes"));
    };
    let (computed, other_order) = match reference.shape() {
        Shape::Checksum(bits) => {
            let value = reference.checksum(&data, big_endian);
            let little = value.to_le_bytes()[..(bits / 8) as usize].to_vec();
            let big: Vec<u8> = little.iter().rev().copied().collect();
            if big_endian { (big, Some(little)) } else { (little, Some(big)) }
        }
        Shape::Digest(_) => (reference.digest(&data), None),
        _ => return Outcome::invalid("a region claim names a checksum, CRC or digest"),
    };
    let Some(found) = project.binary.read(stored, computed.len() as u64) else {
        return Outcome::invalid(format!("the stored value at {stored:#x} is not backed by image bytes"));
    };
    let method = format!(
        "{} recomputed over the image bytes of the range and compared with the stored value",
        reference.describe()
    );
    let mut evidence = json!({
        "range": [address(start), address(end)],
        "stored_at": address(stored),
        "stored": hex(found),
        "computed": hex(&computed),
        "byte_order": if computed.len() > 1 && matches!(reference.shape(), Shape::Checksum(_)) {
            if big_endian { "big" } else { "little" }
        } else {
            "bytes"
        },
    });
    if found == computed.as_slice() {
        return Outcome::verified(Confidence::Exact, method, evidence);
    }
    if other_order.as_deref() == Some(found) {
        evidence["note"] = json!("the stored value is the computed one in the other byte order: claim with endian");
    }
    Outcome::refuted(Confidence::Exact, method, evidence)
}

fn detected(project: &std::sync::Arc<Project>, start: u64, end: u64, reference: Option<&Reference>) -> Outcome {
    let outcome = match project.integrity_checks(&IntegrityRequest::default()) {
        Ok(outcome) => outcome,
        Err(error) => return error.into(),
    };
    let checks = &outcome.report.checks;
    let method = "integrity_checks: stored checksum, CRC and digest fields whose value matches the image".to_owned();
    let algorithm_matches = |name: &str| match reference {
        None => true,
        Some(reference) => Reference::parse(&AlgorithmSpec::Name(name.to_owned())).ok().as_ref() == Some(reference),
    };
    let row = |check: &crate::integrity::IntegrityCheck| {
        json!({
            "id": check.id,
            "algorithm": check.algorithm,
            "stored_at": address(check.stored.address),
            "ranges": check.ranges.iter().map(|range| [address(range.start), address(range.end)]).collect::<Vec<_>>(),
            "valid": check.valid,
            "confidence": check.confidence,
        })
    };
    let covering = checks.iter().find(|check| {
        check.space == "memory"
            && algorithm_matches(check.algorithm)
            && check.ranges.iter().any(|range| range.start <= start && end <= range.end)
    });
    if let Some(check) = covering {
        return Outcome::verified(
            Confidence::Exact,
            format!("{method}: the stored value equals the algorithm over a range that covers the claimed one"),
            json!({"check": row(check)}),
        );
    }
    let overlapping: Vec<Value> = checks
        .iter()
        .filter(|check| check.ranges.iter().any(|range| range.start < end && start < range.end))
        .take(SHOWN)
        .map(row)
        .collect();
    let evidence = json!({"checks_found": checks.len(), "overlapping": overlapping});
    Outcome::unknown(
        method,
        evidence,
        "no detected check covers the range with that algorithm; detection is a search, not proof of absence",
    )
    .needs("stored: the address of the value with an algorithm, to recompute it exactly")
}

pub(crate) fn lock(project: &Project, claim: &LockClaim) -> Outcome {
    let function = match function_start(project, &claim.function) {
        Ok(function) => function,
        Err(outcome) => return outcome,
    };
    let name = project.function_name(function);
    let analysis = match project.analysis() {
        Ok(analysis) => analysis,
        Err(error) => return error.into(),
    };
    let mut mechanisms = Vec::new();
    let mut offset = 0;
    let mut supported = true;
    loop {
        let report = match project.lock_mechanisms(&LockQuery { category: claim.category.clone(), offset, limit: 100 })
        {
            Ok(report) => report,
            Err(error) => return error.into(),
        };
        supported &= report.supported;
        mechanisms.extend(report.mechanisms);
        match report.next_offset {
            Some(next) if next > offset && mechanisms.len() < 1000 => offset = next,
            _ => break,
        }
    }
    let method =
        "lock_mechanisms: decisions that refuse a repair (signature, MAC, chip-ID, anti-rollback, debug lock) \
                  and what each path does"
            .to_owned();
    if !supported {
        return Outcome::unknown(method, Value::Null, "lock tracing does not support this architecture")
            .needs("a disassembly read of the function");
    }
    // A mechanism decides in the function, or one of its outcomes transfers into or calls it.
    let relation = |mechanism: &crate::LockMechanism| -> Option<&'static str> {
        if mechanism.decision.as_ref().is_some_and(|decision| decision.function == function) {
            return Some("decides_in");
        }
        let guards = mechanism.outcomes.iter().any(|outcome| {
            analysis.function_containing(outcome.at) == Some(function) || outcome.detail.contains(name.as_str())
        });
        guards.then_some("guards")
    };
    let related: Vec<(&'static str, &crate::LockMechanism)> =
        mechanisms.iter().filter_map(|mechanism| relation(mechanism).map(|kind| (kind, mechanism))).collect();
    let row = |(kind, mechanism): &(&'static str, &crate::LockMechanism)| {
        json!({
            "relation": kind,
            "id": mechanism.id,
            "category": mechanism.category,
            "confidence": mechanism.confidence,
            "summary": mechanism.summary,
            "decision": mechanism.decision.as_ref().map(|decision| address(decision.at)),
        })
    };
    if let Some(high) = related.iter().find(|(_, mechanism)| mechanism.confidence == "high") {
        return Outcome::verified(Confidence::Heuristic, method, json!({"mechanism": row(high)}));
    }
    if related.is_empty() {
        return Outcome::unknown(
            method,
            json!({"mechanisms_found": mechanisms.len()}),
            format!("no mechanism lock_mechanisms reports decides in or guards {name}; it is a heuristic search"),
        )
        .needs("the decision site: read the function's callers with xrefs, then a calls claim with before");
    }
    let rows: Vec<Value> = related.iter().take(SHOWN).map(row).collect();
    Outcome::unknown(method, json!({"mechanisms": rows}), "the related mechanisms are not of high confidence")
        .needs("the decision read in the disassembly, or a returns claim on the check routine")
}

/// The member `path` of `entry`'s fields (a project or native type), as (offset, size, type).
fn library_member(entry: &Value, path: &str) -> Option<(u64, Option<u64>, String)> {
    let field = entry["fields"].as_array()?.iter().find(|field| field["name"] == path)?;
    Some((field["offset"].as_u64()?, field["size"].as_u64(), field["type_name"].as_str().unwrap_or("").to_owned()))
}

pub(crate) fn layout(project: &Project, claim: &LayoutClaim) -> Outcome {
    let expected_offset = match claim.offset.as_ref().map(|offset| match offset {
        Address::Number(value) => Ok(*value),
        Address::Text(text) => {
            super::run::parse_integer(&crate::evaluate::IntegerText::Text(text.clone())).map(|(value, _)| value)
        }
    }) {
        Some(Err(error)) => return Outcome::invalid(error),
        Some(Ok(offset)) => Some(offset),
        None => None,
    };
    if expected_offset.is_none() && claim.size.is_none() {
        return Outcome::invalid("a layout claim states the member's offset or size");
    }
    // The project type library first, then embedded DWARF or Go type metadata.
    let (found, source) = match project.get_type(&claim.type_name) {
        Ok(entry) => {
            let entry = serde_json::to_value(&entry).unwrap_or_default();
            match library_member(&entry, &claim.member) {
                Some(found) => (vec![found], "the project type library".to_owned()),
                None => {
                    return Outcome::invalid(format!(
                        "{} has no member {:?} in the project type library",
                        claim.type_name, claim.member
                    ));
                }
            }
        }
        Err(_) => match crate::tools::type_member(project, &claim.type_name, &claim.member) {
            Ok(view) => {
                let selections: Vec<(u64, Option<u64>, String)> = view["definitions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|definition| {
                        let selection = &definition["selection"];
                        Some((
                            selection["offset"].as_u64()?,
                            selection["byte_size"].as_u64(),
                            selection["type_name"].as_str().unwrap_or("").to_owned(),
                        ))
                    })
                    .collect();
                if selections.is_empty() {
                    return Outcome::invalid(format!("{} has no member {:?}", claim.type_name, claim.member));
                }
                let source = match view["source"].as_str() {
                    Some("dwarf") => "embedded DWARF".to_owned(),
                    Some("go_runtime") => "Go runtime type metadata".to_owned(),
                    Some(other) => other.to_owned(),
                    None => "debug information".to_owned(),
                };
                (selections, source)
            }
            Err(error) => return error.into(),
        },
    };
    let method = format!("the layout of {} from {source}", claim.type_name);
    let rows: Vec<Value> = found
        .iter()
        .map(|(offset, size, type_name)| json!({"offset": offset, "size": size, "type": type_name}))
        .collect();
    let evidence = json!({"member": claim.member, "layouts": rows});
    let agrees = |(offset, size, _): &(u64, Option<u64>, String)| {
        expected_offset.is_none_or(|expected| expected == *offset)
            && claim.size.is_none_or(|expected| size.is_some_and(|size| size == expected))
    };
    let all = found.iter().all(agrees);
    let none = found.iter().all(|layout| !agrees(layout));
    if all {
        return Outcome::verified(Confidence::Exact, method, evidence);
    }
    if none && found.iter().all(|(_, size, _)| claim.size.is_none() || size.is_some()) {
        return Outcome::refuted(Confidence::Exact, method, evidence);
    }
    Outcome::unknown(method, evidence, "distinct definitions with this name disagree, or the size is not recorded")
        .needs("the definition meant: its unit or a more specific type name")
}
