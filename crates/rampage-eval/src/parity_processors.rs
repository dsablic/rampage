//! Processor roster section of the parity report: every Sleigh roster fixture measured through the ordinary
//! Raw `Project` path (not the explicit-window path), against the owned truth and the seeded Ghidra oracle.
//!
//! Each fixture is opened twice: "manual" seeds every truth entry (measuring retention and extents, not
//! discovery), and "call_only" supplies only the base entry so callees must be found by following calls.
//! Every extent miss is attributed to the decode gates that stopped analysis; a miss with no gate is reported
//! as `unexplained`, never silently accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use rampage_api::{FunctionsQuery, Project};
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PILOT_DIRECTORY: &str = "tests/fixtures/sleigh";
const EXTENDED_DIRECTORY: &str = "tests/fixtures/sleigh/extended";
/// Upper bound on the single decompile attempted per fixture; a stuck attempt is cancelled and reported.
const DECOMPILE_BOUND: Duration = Duration::from_secs(120);

pub const LIMITS: &[&str] = &[
    "Ghidra oracle = seeded function creation; Ghidra autonomous auto-analysis not run",
    "fixtures are hand-assembled byte ledgers; no cross-compilers available",
    "manual seeds supply every truth entry and measure retention and extents, not autonomous entry discovery",
    "call_only seeds supply only the base entry; callees count only when reached by followed calls",
    "decompilation support is one bounded attempt at the first truth entry, not a C correctness verdict",
];

struct Fixture {
    name: String,
    profile: RawProfile,
    base: u64,
    bytes: Vec<u8>,
    functions: Vec<(u64, u64)>,
    ghidra_seeded_functions: usize,
    files: Vec<(&'static str, String)>,
}

#[derive(Default)]
struct Outcome {
    retained: usize,
    exact: usize,
    misses: Vec<Value>,
    miss_reasons: BTreeMap<String, usize>,
    gates: Vec<Value>,
}

/// Measures the whole roster from the repository root and returns the `processor_roster` section.
pub fn measure(root: &Path) -> Result<Value, String> {
    let fixtures = fixtures(root)?;
    let mut rows = Vec::new();
    let mut totals = [0usize; 5];
    for fixture in &fixtures {
        let entries: Vec<u64> = fixture.functions.iter().map(|(entry, _)| *entry).collect();
        let manual = project(fixture, None, entries.clone())?;
        let manual_outcome = measure_project(fixture, &manual)?;
        let call_only = project(fixture, Some(fixture.base), vec![])?;
        let call_outcome = measure_project(fixture, &call_only)?;
        let decompile = decompile(&manual, entries[0]);
        for (total, value) in totals.iter_mut().zip([
            entries.len(),
            manual_outcome.retained,
            manual_outcome.exact,
            call_outcome.retained,
            call_outcome.exact,
        ]) {
            *total += value;
        }
        let files = fixture
            .files
            .iter()
            .map(|(role, path)| Ok(json!({"role": role, "path": path, "sha256": hash(&root.join(path))?})))
            .collect::<Result<Vec<_>, String>>()?;
        rows.push(json!({
            "fixture": fixture.name,
            "language_id": fixture.profile.language_id(),
            "admission": "project",
            "files": files,
            "truth_entries": entries.len(),
            "ghidra_seeded_functions": fixture.ghidra_seeded_functions,
            "manual": outcome_json(&manual_outcome),
            "call_only": outcome_json(&call_outcome),
            "decompile": decompile,
        }));
    }
    let decompile_ok: Vec<_> =
        rows.iter().filter(|row| row["decompile"]["status"] == "ok").map(|row| row["fixture"].clone()).collect();
    Ok(json!({
        "schema_version": 1,
        "admission_path": "ordinary Raw Project (Binary::from_raw_code + rampage_api::Project), not the window path",
        "fixtures": rows.len(),
        "totals": {
            "truth_entries": totals[0],
            "manual": {"retained": totals[1], "exact_extents": totals[2]},
            "call_only": {"retained": totals[3], "exact_extents": totals[4]},
            "decompile_ok": decompile_ok,
        },
        "rows": rows,
        "limits": LIMITS,
    }))
}

fn outcome_json(outcome: &Outcome) -> Value {
    json!({
        "retained": outcome.retained, "exact_extents": outcome.exact,
        "misses_by_gate_reason": outcome.miss_reasons, "misses": outcome.misses, "gates": outcome.gates,
    })
}

fn fixtures(root: &Path) -> Result<Vec<Fixture>, String> {
    let read = |relative: &str| -> Result<Value, String> {
        let bytes = std::fs::read(root.join(relative)).map_err(|error| format!("{relative}: {error}"))?;
        serde_json::from_slice(&bytes).map_err(|error| format!("{relative}: {error}"))
    };
    let field = |value: &Value, key: &str| -> Result<u64, String> {
        value[key].as_u64().ok_or_else(|| format!("fixture field {key} is not an integer"))
    };
    let parse_base = |fixture: &Value| -> Result<u64, String> {
        let text = fixture["base_byte_offset"].as_str().ok_or("fixture has no base_byte_offset")?;
        u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|error| error.to_string())
    };
    let profile = |fixture: &Value| -> Result<RawProfile, String> {
        let id = fixture["language_id"].as_str().ok_or("fixture has no language_id")?;
        RawProfile::from_language_id(id).map_err(|error| format!("{id}: {error}"))
    };
    let mut all = Vec::new();
    let pilot_truth = read(&format!("{PILOT_DIRECTORY}/truth.json"))?;
    let pilot_oracle = read(&format!("{PILOT_DIRECTORY}/oracle.json"))?;
    for fixture in pilot_truth["fixtures"].as_array().ok_or("pilot truth has no fixtures")? {
        let name = fixture["name"].as_str().ok_or("pilot fixture has no name")?.to_owned();
        let base = parse_base(fixture)?;
        let functions = fixture["functions"]
            .as_array()
            .ok_or("pilot fixture has no functions")?
            .iter()
            .map(|function| {
                Ok((
                    base + field(function, "entry_offset_bytes")?,
                    base + field(function, "extent_end_exclusive_bytes")?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let oracle = pilot_oracle["fixtures"]
            .as_array()
            .and_then(|fixtures| fixtures.iter().find(|candidate| candidate["name"] == name.as_str()))
            .ok_or_else(|| format!("{name}: no pilot oracle row"))?;
        let seeded = oracle["program_oracle"]["functions"].as_array().ok_or("pilot oracle has no functions")?.len();
        let bin = format!("{PILOT_DIRECTORY}/{}", fixture["bytes_file"].as_str().ok_or("pilot has no bytes_file")?);
        all.push(Fixture {
            profile: profile(fixture)?,
            base,
            bytes: std::fs::read(root.join(&bin)).map_err(|error| format!("{bin}: {error}"))?,
            functions,
            ghidra_seeded_functions: seeded,
            files: vec![
                ("bytes", bin),
                ("truth", format!("{PILOT_DIRECTORY}/truth.json")),
                ("oracle", format!("{PILOT_DIRECTORY}/oracle.json")),
                ("provenance", format!("{PILOT_DIRECTORY}/provenance.json")),
            ],
            name,
        });
    }
    let extended = read(&format!("{EXTENDED_DIRECTORY}/truth-current.json"))?;
    for current in extended["fixtures"].as_array().ok_or("extended truth has no fixtures")? {
        let name = current["name"].as_str().ok_or("extended fixture has no name")?.to_owned();
        let truth_path = format!("{EXTENDED_DIRECTORY}/{name}.truth.json");
        let oracle_path = format!("{EXTENDED_DIRECTORY}/{name}.oracle.json");
        let fixture = read(&truth_path)?;
        if &fixture != current {
            return Err(format!("{truth_path} differs from truth-current.json"));
        }
        let base = parse_base(&fixture)?;
        let functions = fixture["functions"]
            .as_array()
            .ok_or("extended fixture has no functions")?
            .iter()
            .map(|function| {
                Ok((base + field(function, "start_bytes")?, base + field(function, "end_exclusive_bytes")?))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let oracle = read(&oracle_path)?;
        if oracle["verdict"]["status"] != "pass" {
            return Err(format!("{oracle_path}: oracle verdict is not pass"));
        }
        let seeded = field(&oracle["verdict"], "observed_function_count")? as usize;
        let bin = format!("{EXTENDED_DIRECTORY}/{name}.bin");
        all.push(Fixture {
            profile: profile(&fixture)?,
            base,
            bytes: std::fs::read(root.join(&bin)).map_err(|error| format!("{bin}: {error}"))?,
            functions,
            ghidra_seeded_functions: seeded,
            files: vec![
                ("bytes", bin),
                ("truth", truth_path),
                ("oracle", oracle_path),
                ("provenance", format!("{EXTENDED_DIRECTORY}/{name}.provenance.json")),
            ],
            name,
        });
    }
    Ok(all)
}

fn project(fixture: &Fixture, entry: Option<u64>, seeds: Vec<u64>) -> Result<Project, String> {
    let options = RawCodeOptions { profile: fixture.profile, base: fixture.base, entry, seeds };
    let binary = Binary::from_raw_code(fixture.bytes.clone(), options)
        .map_err(|error| format!("{}: Raw admission refused: {error}", fixture.name))?;
    Ok(Project::new(binary))
}

fn gate_reason(gate: &rampage_arch::DecodeGate) -> String {
    serde_json::to_value(gate.reason).ok().and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_default()
}

fn measure_project(fixture: &Fixture, project: &Project) -> Result<Outcome, String> {
    let fail = |error: rampage_api::ApiError| format!("{}: {error}", fixture.name);
    let rows = project.functions(&FunctionsQuery::default()).map_err(fail)?;
    let mut outcome = Outcome::default();
    let mut all_reasons = BTreeSet::new();
    for row in &rows.items {
        for line in project.function_listing(row.address).map_err(fail)?.blocks.iter().flatten() {
            if let Some(gate) = line.decode_gate {
                all_reasons.insert(gate_reason(&gate));
                outcome.gates.push(json!({
                    "function": format!("{:#x}", row.address), "address": format!("{:#x}", gate.address),
                    "reason": gate_reason(&gate),
                }));
            }
        }
    }
    for &(entry, end) in &fixture.functions {
        let (kind, reasons) = if rows.items.iter().any(|row| row.address == entry) {
            outcome.retained += 1;
            let listing = project.function_listing(entry).map_err(fail)?;
            let mut covered = BTreeSet::new();
            for line in listing.blocks.iter().flatten() {
                covered.extend(line.address..line.address + line.bytes.len() as u64 / 2);
            }
            if covered == (entry..end).collect::<BTreeSet<_>>() {
                outcome.exact += 1;
                continue;
            }
            let reasons: BTreeSet<_> = listing
                .blocks
                .iter()
                .flatten()
                .filter_map(|line| line.decode_gate.map(|gate| gate_reason(&gate)))
                .collect();
            ("extent_mismatch", reasons)
        } else {
            ("not_retained", all_reasons.clone())
        };
        let reasons: Vec<String> =
            if reasons.is_empty() { vec!["unexplained".to_owned()] } else { reasons.into_iter().collect() };
        for reason in &reasons {
            *outcome.miss_reasons.entry(reason.clone()).or_default() += 1;
        }
        outcome.misses.push(json!({"entry": format!("{entry:#x}"), "kind": kind, "gate_reasons": reasons}));
    }
    Ok(outcome)
}

/// One cancellable decompile attempt; the outcome is the API's own behaviour, recorded rather than judged.
fn decompile(project: &Project, entry: u64) -> Value {
    let cancel = AtomicBool::new(false);
    let (done, finished) = mpsc::channel::<()>();
    let result = std::thread::scope(|scope| {
        let cancel = &cancel;
        scope.spawn(move || {
            if finished.recv_timeout(DECOMPILE_BOUND).is_err() {
                cancel.store(true, Ordering::Relaxed);
            }
        });
        let result = project.decompile_cancellable(entry, cancel);
        let _ = done.send(());
        result
    });
    let timed_out = cancel.load(Ordering::Relaxed);
    match result {
        Ok(decompilation) => json!({
            "entry": format!("{entry:#x}"), "status": "ok", "language_id": decompilation.language_id,
            "c_bytes": decompilation.code.len(),
        }),
        Err(error) => json!({
            "entry": format!("{entry:#x}"), "status": if timed_out { "timed_out" } else { "refused" },
            "reason": error.to_string(),
        }),
    }
}

fn hash(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(rampage_arch::hex::bytes(&Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_section_matches_the_project_matrix() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let section = measure(&root).unwrap();
        let rows = section["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 16);
        assert_eq!(rows.len(), RawProfile::ALL.len());
        let totals = &section["totals"];
        assert_eq!(totals["truth_entries"], 32);
        assert_eq!(totals["manual"], json!({"retained": 32, "exact_extents": 23}));
        assert_eq!(totals["call_only"], json!({"retained": 27, "exact_extents": 20}));
        assert_eq!(totals["decompile_ok"], json!(["msp430", "avr8"]));
        for row in rows {
            assert_eq!(row["admission"], "project");
            assert_eq!(row["ghidra_seeded_functions"], row["truth_entries"], "{}", row["fixture"]);
            for mode in ["manual", "call_only"] {
                assert!(row[mode]["misses_by_gate_reason"].get("unexplained").is_none(), "{} {mode}", row["fixture"]);
            }
            if row["decompile"]["status"] != "ok" {
                assert_eq!(row["decompile"]["status"], "refused", "{}", row["fixture"]);
                let reason = row["decompile"]["reason"].as_str().unwrap();
                assert_eq!(reason, format!("no reviewed C model for {}", row["language_id"].as_str().unwrap()));
            }
            for file in row["files"].as_array().unwrap() {
                assert!(!Path::new(file["path"].as_str().unwrap()).is_absolute());
                assert_eq!(file["sha256"].as_str().unwrap().len(), 64);
            }
        }
        let languages: BTreeSet<_> = rows.iter().map(|row| row["language_id"].as_str().unwrap()).collect();
        let roster: BTreeSet<_> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
        assert_eq!(languages, roster);
        let hexagon = rows.iter().find(|row| row["fixture"] == "Hexagon-v2").unwrap();
        assert_eq!(hexagon["manual"]["misses_by_gate_reason"], json!({"processor_helper_required": 2}));
    }
}
