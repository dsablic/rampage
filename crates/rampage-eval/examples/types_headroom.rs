//! Measurement only: how much of the parameter type class gap against DWARF is reachable, and how much a
//! one-feature miner over the decompiler's own answer already takes (docs/plans/2026-11-20-flywheel-next.md,
//! step 2; report in docs/benchmarks/flywheel-headroom-2026-11-21.md).
//!
//! `cargo run --release -p rampage-eval --example types_headroom -- [--path raw|api] OUT.json ROLE:DEBUG:STRIPPED:TRUTH...`
//!
//! ROLE is `train` or `dev`; TRUTH is `rampage-eval type-truth DEBUG --stripped STRIPPED`. Every truth function is
//! decompiled in the stripped binary, as the `types` eval family does on the same `--path` (default `api`, the MCP
//! decompile tool's project; `raw` is the bare project of the numbers before 2026-11-27), and each declared
//! parameter position is scored by class. `positions` in OUT.json lists every scored position, for diffing two
//! runs. Neither path reads or writes the persistent analysis store. Each wrong or missed position is classified:
//!
//! - `not_decompiled`: no signature at all (not a type problem);
//! - `dead`: DWARF gives the parameter no location, so the callee never reads it and holds no evidence of its
//!   type (reachable only from call sites);
//! - `register_class`: a float where an integer or pointer was recovered, or the reverse, or a missing position:
//!   the ABI register (or its presence) differs, so the callee's code decides it;
//! - `ambiguous`: classes the machine code may not separate (a narrow integer widened, pointer versus integer,
//!   struct pointer versus pointer, a small struct by value versus an integer): reachable only when the body
//!   uses the value in a telling way.
//!
//! Spurious positions (more parameters recovered than declared) are counted on their own.
//!
//! One-feature miners learn, on the `train` binaries, the majority truth class for each value of one feature of
//! the decompiler's answer (its class; its raw spelling; its class at that position) and replace the answer on
//! `dev` with it. They show what remapping the existing answer gets without new analysis.

use std::collections::BTreeMap;
use std::path::PathBuf;

use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};
use rampage_eval::{ProposedSignature, SignaturePath, TypeClass, TypeTruth, signature_batch_on};
use serde_json::json;

/// Per function address: whether each formal parameter has a DWARF location.
fn liveness(data: &[u8]) -> Result<BTreeMap<u64, Vec<bool>>, String> {
    let object = object::File::parse(data).map_err(|error| error.to_string())?;
    let endian = if object.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big };
    let dwarf = Dwarf::load(|id| -> Result<EndianSlice<'_, RunTimeEndian>, String> {
        let data = match object.section_by_name(id.name()) {
            Some(section) => section.data().map_err(|error| format!("{}: {error}", id.name()))?,
            None => &[],
        };
        Ok(EndianSlice::new(data, endian))
    })?;
    let mut out: BTreeMap<u64, Vec<bool>> = BTreeMap::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|error| error.to_string())? {
        let unit = dwarf.unit(header).map_err(|error| error.to_string())?;
        let mut entries = unit.entries();
        let mut open: Option<(isize, u64)> = None;
        while let Some(entry) = entries.next_dfs().map_err(|error| error.to_string())? {
            let depth = entry.depth();
            if open.is_some_and(|(at, _)| depth <= at) {
                open = None;
            }
            if let Some((at, address)) = open {
                if depth == at + 1 && entry.tag() == gimli::DW_TAG_formal_parameter {
                    let live = entry.has_attr(gimli::DW_AT_location) || entry.has_attr(gimli::DW_AT_const_value);
                    out.entry(address).or_default().push(live);
                }
                continue;
            }
            if entry.tag() != gimli::DW_TAG_subprogram
                || entry.has_attr(gimli::DW_AT_abstract_origin)
                || entry.has_attr(gimli::DW_AT_specification)
            {
                continue;
            }
            let Some(low_pc) = entry.attr_value(gimli::DW_AT_low_pc) else { continue };
            let Some(address) = dwarf.attr_address(&unit, low_pc).map_err(|error| error.to_string())? else {
                continue;
            };
            if out.contains_key(&address) {
                continue;
            }
            out.insert(address, Vec::new());
            open = Some((depth, address));
        }
    }
    Ok(out)
}

fn is_float(class: TypeClass) -> bool {
    class.tag().starts_with("float")
}

/// One scored declared position.
struct Position {
    arch: String,
    index: usize,
    truth: TypeClass,
    proposed: Option<(TypeClass, String)>,
    live: bool,
    decompiled: bool,
}

fn category(position: &Position) -> &'static str {
    match &position.proposed {
        Some((class, _)) if *class == position.truth => "correct",
        _ if !position.decompiled => "not_decompiled",
        _ if !position.live => "dead",
        None => "register_class",
        Some((class, _)) if is_float(*class) != is_float(position.truth) => "register_class",
        Some(_) => "ambiguous",
    }
}

type Miner = BTreeMap<String, BTreeMap<String, u64>>;

fn feature(kind: &str, position: &Position) -> Option<String> {
    let (class, raw) = position.proposed.as_ref()?;
    Some(match kind {
        "class" => format!("{}|{}", position.arch, class.tag()),
        "raw" => format!("{}|{raw}", position.arch),
        "class_at_position" => format!("{}|{}|{}", position.arch, position.index.min(3), class.tag()),
        _ => unreachable!(),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1).peekable();
    let path = if args.peek().map(String::as_str) == Some("--path") {
        args.next();
        match args.next().as_deref() {
            Some("raw") => SignaturePath::Raw,
            Some("api") => SignaturePath::Api,
            other => return Err(format!("--path takes raw or api, not {other:?}").into()),
        }
    } else {
        SignaturePath::Api
    };
    let out = PathBuf::from(args.next().ok_or("OUT.json")?);
    let mut rows = Vec::new();
    let mut positions: BTreeMap<String, Vec<Position>> = BTreeMap::new();
    let mut spurious: BTreeMap<String, u64> = BTreeMap::new();
    let mut per_binary = serde_json::Map::new();
    for spec in args {
        let parts: Vec<&str> = spec.splitn(4, ':').collect();
        let [role, debug, stripped, truth] = parts[..] else { return Err(format!("bad spec {spec}").into()) };
        let truth = TypeTruth::from_json(&std::fs::read_to_string(truth)?)?;
        let live = liveness(&std::fs::read(debug)?)?;
        let arch = rampage_loaders::Binary::open(std::path::Path::new(stripped))?.arch.to_string();
        let started = std::time::Instant::now();
        let proposals = signature_batch_on(path, std::path::Path::new(stripped), truth.0.keys().copied())?.signatures;
        let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
        for (address, declared) in &truth.0 {
            let proposed: Option<&ProposedSignature> = proposals.get(address).and_then(|result| result.as_ref().ok());
            let flags = live.get(address);
            for (index, class) in declared.params.iter().enumerate() {
                let position = Position {
                    arch: arch.clone(),
                    index,
                    truth: *class,
                    proposed: proposed
                        .and_then(|signature| signature.params.get(index))
                        .map(|param| (param.class, param.raw.clone())),
                    live: flags.and_then(|flags| flags.get(index)).copied().unwrap_or(true),
                    decompiled: proposed.is_some(),
                };
                *counts.entry(category(&position)).or_default() += 1;
                rows.push(json!({
                    "binary": stripped, "function": declared.name, "address": format!("{address:#x}"), "index": index,
                    "truth": class.tag(), "proposed": position.proposed.as_ref().map(|(class, _)| class.tag()),
                    "raw": position.proposed.as_ref().map(|(_, raw)| raw), "category": category(&position),
                }));
                positions.entry(role.to_owned()).or_default().push(position);
            }
            if let Some(proposed) = proposed
                && proposed.params.len() > declared.params.len()
            {
                let extra = (proposed.params.len() - declared.params.len()) as u64;
                *spurious.entry(role.to_owned()).or_default() += extra;
                *counts.entry("spurious").or_default() += extra;
            }
        }
        eprintln!("{stripped}: {} functions, {:.0}s, {counts:?}", truth.0.len(), started.elapsed().as_secs_f64());
        per_binary.insert(stripped.to_owned(), json!({"role": role, "functions": truth.0.len(), "counts": counts}));
    }

    // Classification per role.
    let mut summary = serde_json::Map::new();
    for (role, list) in &positions {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut pairs: BTreeMap<String, u64> = BTreeMap::new();
        for position in list {
            let category = category(position);
            *counts.entry(category.to_owned()).or_default() += 1;
            if category != "correct" {
                let proposed = position.proposed.as_ref().map_or("none", |(class, _)| class.tag());
                *pairs.entry(format!("{category}: {}->{proposed}", position.truth.tag())).or_default() += 1;
            }
        }
        summary.insert(
            role.clone(),
            json!({"positions": list.len(), "spurious": spurious.get(role), "counts": counts, "pairs": pairs}),
        );
    }

    // One-feature miners: train on `train`, apply to `dev`.
    let mut miners = serde_json::Map::new();
    let train = positions.get("train").map(Vec::as_slice).unwrap_or_default();
    let dev = positions.get("dev").map(Vec::as_slice).unwrap_or_default();
    for kind in ["class", "raw", "class_at_position"] {
        let mut table: Miner = BTreeMap::new();
        for position in train {
            if let Some(value) = feature(kind, position) {
                *table.entry(value).or_default().entry(position.truth.tag().to_owned()).or_default() += 1;
            }
        }
        let predict = |position: &Position| -> Option<String> {
            let value = feature(kind, position)?;
            let counts = table.get(&value)?;
            counts.iter().max_by_key(|(_, count)| **count).map(|(class, _)| class.clone())
        };
        let (mut before, mut after, mut fixed, mut broken) = (0u64, 0u64, 0u64, 0u64);
        let mut fixed_by_category: BTreeMap<&str, u64> = BTreeMap::new();
        for position in dev {
            let was = category(position) == "correct";
            let now = match predict(position) {
                Some(class) => class == position.truth.tag(),
                None => was,
            };
            before += u64::from(was);
            after += u64::from(now);
            if now && !was {
                fixed += 1;
                *fixed_by_category.entry(category(position)).or_default() += 1;
            }
            if was && !now {
                broken += 1;
            }
        }
        let rules: BTreeMap<String, String> = table
            .iter()
            .filter_map(|(value, counts)| {
                let (class, _) = counts.iter().max_by_key(|(_, count)| **count)?;
                Some((value.clone(), class.clone()))
            })
            .filter(|(value, class)| !value.ends_with(&format!("|{class}")))
            .collect();
        miners.insert(
            kind.to_owned(),
            json!({"dev_correct_before": before, "dev_correct_after": after, "fixed": fixed, "broken": broken,
                   "fixed_by_category": fixed_by_category, "changing_rules": rules}),
        );
    }
    let report = json!({"path": path.tag(), "binaries": per_binary, "summary": summary, "miners": miners,
                        "positions": rows});
    std::fs::write(&out, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
