use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use rampage_eval::{Report, Truth, proposals, score};
use rampage_loaders::Binary;
use rampage_signatures::SignatureDb;
use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use serde_json::{Value, json};

mod signature_corpus_support;
use signature_corpus_support::{digest, verify_twin};

const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 1024 * 1024 - 1;

#[derive(Parser)]
struct Arguments {
    #[arg(long = "database", required = true)]
    databases: Vec<PathBuf>,
    #[arg(long = "case", required = true)]
    cases: Vec<PathBuf>,
    #[arg(long = "target", required = true)]
    targets: Vec<PathBuf>,
    #[arg(long = "symbolized", required = true)]
    symbolized: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    report: PathBuf,
}

// Builder reports can add fields; every field used as evidence here is required and typed.
#[derive(Deserialize)]
struct CaseReport {
    schema_version: u32,
    measurement: String,
    collector_source_sha256: String,
    collector_support_sha256: String,
    evaluator_binary_sha256: String,
    arch: String,
    scheme: u32,
    reference_sha256: String,
    symbolized_target_sha256: String,
    stripped_target_sha256: String,
    database_sha256: String,
    compressed_database_sha256: String,
    database_bytes: usize,
    compressed_database_bytes: usize,
    library_object_count: usize,
    library_object_sha256: Vec<String>,
    truth_functions: usize,
    library_truth: StrictTruth,
    load_image_equivalent_stripped_twin: bool,
    target_executed: bool,
    baseline: Report,
    after: Report,
}

struct StrictTruth(Truth);

impl<'de> Deserialize<'de> for StrictTruth {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TruthVisitor;
        impl<'de> Visitor<'de> for TruthVisitor {
            type Value = StrictTruth;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a unique canonical hex-address to nonempty name map")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut truth = BTreeMap::new();
                while let Some((key, name)) = map.next_entry::<String, String>()? {
                    let address = key
                        .strip_prefix("0x")
                        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
                        .ok_or_else(|| serde::de::Error::custom("invalid truth address"))?;
                    if key != format!("{address:#x}")
                        || name.is_empty()
                        || name.len() > 4096
                        || name.contains('\0')
                        || truth.len() >= 100_000
                        || truth.insert(address, name).is_some()
                    {
                        return Err(serde::de::Error::custom("invalid, duplicate or oversized library truth"));
                    }
                }
                Ok(StrictTruth(Truth(truth)))
            }
        }
        deserializer.deserialize_map(TruthVisitor)
    }
}

fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!("{}: expected a regular file of at most {limit} bytes", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err(format!("{}: source changed length while reading", path.display()));
    }
    Ok(bytes)
}

fn parse_case(bytes: &[u8]) -> Result<CaseReport, String> {
    let case: CaseReport = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let hashes = [
        &case.collector_source_sha256,
        &case.collector_support_sha256,
        &case.evaluator_binary_sha256,
        &case.reference_sha256,
        &case.symbolized_target_sha256,
        &case.stripped_target_sha256,
        &case.database_sha256,
        &case.compressed_database_sha256,
    ];
    if case.schema_version != 1
        || case.measurement != "phase2-1-library-signatures"
        || !case.load_image_equivalent_stripped_twin
        || case.target_executed
        || hashes.into_iter().any(|hash| !is_digest(hash))
        || case.library_object_sha256.iter().any(|hash| !is_digest(hash))
        || case.library_object_count == 0
        || case.library_object_count > 1024
        || case.library_object_count != case.library_object_sha256.len()
        || case.truth_functions == 0
        || case.truth_functions != case.library_truth.0.0.len()
        || case.reference_sha256 == case.symbolized_target_sha256
        || case.reference_sha256 == case.stripped_target_sha256
    {
        return Err("case is not a bounded, hash-bound signature_corpus builder report".into());
    }
    let arch: rampage_arch::Arch = case.arch.parse().map_err(|_| "invalid case architecture")?;
    if case.arch != arch.to_string() {
        return Err("noncanonical case architecture".into());
    }
    Ok(case)
}

struct DatabaseInput {
    path: PathBuf,
    sha256: String,
    json_sha256: String,
    compressed_bytes: usize,
    json_bytes: usize,
    database: SignatureDb,
}

fn load_databases(paths: &[PathBuf]) -> Result<Vec<DatabaseInput>, String> {
    let mut inputs = Vec::new();
    let mut seen = BTreeSet::new();
    for path in paths {
        let bytes = read_bounded(path, MAX_DATABASE_BYTES)?;
        let sha256 = digest(&bytes);
        if !seen.insert(sha256.clone()) {
            return Err("duplicate compressed database hash; provide each database once".into());
        }
        let database = SignatureDb::from_gzip(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
        let json = database.to_json();
        inputs.push(DatabaseInput {
            path: path.clone(),
            sha256,
            json_sha256: digest(json.as_bytes()),
            compressed_bytes: bytes.len(),
            json_bytes: json.len(),
            database,
        });
    }
    inputs.sort_by(|left, right| left.sha256.cmp(&right.sha256));
    let first = inputs.first().ok_or("at least one database is required")?;
    for input in &inputs {
        if input.database.arch() != first.database.arch() || input.database.scheme() != first.database.scheme() {
            return Err("database ARCH/SCHEME mismatch".into());
        }
    }
    Ok(inputs)
}

fn export_combination<'a>(databases: impl IntoIterator<Item = &'a SignatureDb>) -> Result<Vec<u8>, String> {
    let mut databases = databases.into_iter();
    let mut aggregate = databases.next().ok_or("empty aggregate")?.clone();
    for database in databases {
        aggregate.combine(database).map_err(|error| error.to_string())?;
    }
    aggregate.to_gzip().map_err(|error| error.to_string())
}

fn index_hashes(entries: impl IntoIterator<Item = (String, PathBuf)>) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut index = BTreeMap::new();
    for (hash, path) in entries {
        if index.insert(hash, path).is_some() {
            return Err("reused/ambiguous image hash; provide each target and symbolized twin exactly once".into());
        }
    }
    Ok(index)
}

fn resolve_hash<'a>(index: &'a BTreeMap<String, PathBuf>, hash: &str) -> Result<&'a Path, String> {
    index.get(hash).map(PathBuf::as_path).ok_or_else(|| format!("missing image with SHA-256 {hash}"))
}

fn image_index(paths: &[PathBuf]) -> Result<BTreeMap<String, PathBuf>, String> {
    index_hashes(
        paths
            .iter()
            .map(|path| Ok((digest(&read_bounded(path, MAX_IMAGE_BYTES)?), path.clone())))
            .collect::<Result<Vec<_>, String>>()?,
    )
}

fn open_bound(path: &Path, expected_hash: &str) -> Result<Binary, String> {
    let bytes = read_bounded(path, MAX_IMAGE_BYTES)?;
    if bytes.get(..4) != Some(b"\x7fELF") || digest(&bytes) != expected_hash {
        return Err(format!("{}: expected the bounded hash-bound ELF source", path.display()));
    }
    drop(bytes);
    let binary = Binary::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    binary.validate_backing_source().map_err(|error| error.to_string())?;
    if binary.format != rampage_loaders::Format::Elf
        || binary.image_bytes().len() as u64 > MAX_IMAGE_BYTES
        || digest(binary.image_bytes()) != expected_hash
    {
        return Err(format!("{}: expected the hash-bound ELF image", path.display()));
    }
    Ok(binary)
}

fn grade(proposed: &[(u64, Option<String>)], owned: &Truth, full: &Truth) -> (Report, Report, bool) {
    let mut owned_report = score(proposed.iter().filter(|(address, _)| owned.0.contains_key(address)).cloned(), owned);
    // score's generic recall excludes wrong names; this gate keeps the exact builder truth denominator.
    owned_report.recall = owned_report.correct as f64 / owned.0.len().max(1) as f64;
    let mut all_report = score(proposed.iter().cloned(), full);
    all_report.recall = all_report.correct as f64 / full.0.len().max(1) as f64;
    let passed = !owned.0.is_empty()
        && owned_report.recall >= 0.8
        && owned_report.wrong == 0
        && all_report.wrong == 0
        && all_report.spurious == 0;
    (owned_report, all_report, passed)
}

struct PreparedCase {
    path: PathBuf,
    report_sha256: String,
    case: CaseReport,
    target_path: PathBuf,
    symbolized_path: PathBuf,
    target: Binary,
    symbolized: Binary,
    full_truth: Truth,
}

fn prepare_cases(
    paths: &[PathBuf],
    databases: &[DatabaseInput],
    targets: &BTreeMap<String, PathBuf>,
    symbolized: &BTreeMap<String, PathBuf>,
) -> Result<Vec<PreparedCase>, String> {
    let mut prepared = Vec::new();
    let mut used_targets = BTreeSet::new();
    let mut used_symbolized = BTreeSet::new();
    for path in paths {
        let bytes = read_bounded(path, MAX_REPORT_BYTES)?;
        let case = parse_case(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
        let database = databases
            .iter()
            .find(|input| input.sha256 == case.compressed_database_sha256)
            .ok_or("case's original compressed database SHA-256 is not among --database inputs")?;
        if case.arch != database.database.arch().to_string() || case.scheme != database.database.scheme() {
            return Err("case/reference database ARCH/SCHEME mismatch".into());
        }
        if case.database_sha256 != database.json_sha256
            || case.database_bytes != database.json_bytes
            || case.compressed_database_bytes != database.compressed_bytes
        {
            return Err("case database JSON/compressed size or hash mismatch".into());
        }
        if !used_targets.insert(case.stripped_target_sha256.clone())
            || !used_symbolized.insert(case.symbolized_target_sha256.clone())
        {
            return Err("multiple cases reuse the same image hash; ambiguous target association".into());
        }
        let target_path = resolve_hash(targets, &case.stripped_target_sha256)?.to_owned();
        let symbolized_path = resolve_hash(symbolized, &case.symbolized_target_sha256)?.to_owned();
        let target = open_bound(&target_path, &case.stripped_target_sha256)?;
        let symbolized = open_bound(&symbolized_path, &case.symbolized_target_sha256)?;
        if target.arch.to_string() != case.arch || symbolized.arch.to_string() != case.arch {
            return Err("case/reference/target ARCH mismatch".into());
        }
        let full_truth = Truth::from_binary(&symbolized);
        if full_truth.0.is_empty() || full_truth.0.len() > 100_000 {
            return Err("full symbolized truth is empty or exceeds 100000 functions".into());
        }
        for (address, name) in &case.library_truth.0.0 {
            if full_truth.0.get(address) != Some(name) {
                return Err(format!(
                    "owned/full canonical twin truth differs at {address:#x}; \
                     alias-set reconciliation is unsupported, so frozen owned names cannot be regraded"
                ));
            }
        }
        verify_twin(&symbolized, &target, &full_truth)?;
        prepared.push(PreparedCase {
            path: path.clone(),
            report_sha256: digest(&bytes),
            case,
            target_path,
            symbolized_path,
            target,
            symbolized,
            full_truth,
        });
    }
    if used_targets.len() != targets.len() || used_symbolized.len() != symbolized.len() {
        return Err("unused target or symbolized input; all associations must be exact SHA-256 matches".into());
    }
    prepared.sort_by(|left, right| left.report_sha256.cmp(&right.report_sha256));
    Ok(prepared)
}

fn write_outputs(output: &Path, gzip: &[u8], report: &Path, json: &[u8]) -> Result<(), String> {
    let create = |path: &Path| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("{}: {error}", path.display()))
    };
    let mut artifact = create(output)?;
    let mut receipt = match create(report) {
        Ok(file) => file,
        Err(error) => {
            drop(artifact);
            let _ = std::fs::remove_file(output);
            return Err(error);
        }
    };
    let result = artifact
        .write_all(gzip)
        .and_then(|()| artifact.sync_all())
        .and_then(|()| receipt.write_all(json))
        .and_then(|()| receipt.sync_all());
    drop(artifact);
    drop(receipt);
    if let Err(error) = result {
        let _ = std::fs::remove_file(output);
        let _ = std::fs::remove_file(report);
        return Err(format!("writing aggregate artifacts: {error}"));
    }
    Ok(())
}

fn run(arguments: Arguments) -> Result<(), String> {
    if arguments.databases.is_empty()
        || arguments.databases.len() > 64
        || arguments.cases.is_empty()
        || arguments.cases.len() > 64
        || arguments.targets.len() != arguments.cases.len()
        || arguments.symbolized.len() != arguments.cases.len()
    {
        return Err("require 1..64 databases/cases and exactly one target and symbolized input per case".into());
    }
    if arguments.output == arguments.report {
        return Err("aggregate and report outputs must be distinct".into());
    }
    for path in [&arguments.output, &arguments.report] {
        if path.try_exists().map_err(|error| error.to_string())? {
            return Err(format!("{}: refusing to overwrite an existing artifact", path.display()));
        }
    }
    let databases = load_databases(&arguments.databases)?;
    let targets = image_index(&arguments.targets)?;
    let symbolized = image_index(&arguments.symbolized)?;
    let prepared = prepare_cases(&arguments.cases, &databases, &targets, &symbolized)?;
    let compressed = export_combination(databases.iter().map(|input| &input.database))?;
    let reversed = export_combination(databases.iter().rev().map(|input| &input.database))?;
    let rotated =
        export_combination(databases.iter().cycle().skip(1).take(databases.len()).map(|input| &input.database))?;
    if compressed != reversed || compressed != rotated {
        return Err("aggregate export differs under reversed or rotated database order".into());
    }
    let measured = SignatureDb::from_gzip(&compressed).map_err(|error| error.to_string())?;
    if measured.to_gzip().map_err(|error| error.to_string())? != compressed {
        return Err("aggregate gzip round trip is not deterministic".into());
    }
    let mut passed = true;
    let mut cases = Vec::new();
    for prepared_case in &prepared {
        let case = &prepared_case.case;
        let measurement = match proposals(&measured, &prepared_case.target) {
            Ok(proposed) => {
                let (owned, full, case_passed) = grade(&proposed, &case.library_truth.0, &prepared_case.full_truth);
                passed &= case_passed;
                json!({
                    "owned":owned,"all_proposed_against_full_twin_truth":full,"passed":case_passed,
                    "named_proposals":proposed.iter().filter(|(_, name)|name.is_some()).count(),
                    "other_owned_scope_named_proposals":proposed.iter()
                        .filter(|(address,name)|name.is_some() && !case.library_truth.0.0.contains_key(address)).count()
                })
            }
            Err(error) => {
                passed = false;
                json!({"passed":false,"error":error.to_string()})
            }
        };
        cases.push(json!({
            "case_report":prepared_case.path,"case_report_sha256":prepared_case.report_sha256,
            "arch":case.arch,"scheme":case.scheme,
            "reference_sha256":case.reference_sha256,
            "stripped_target":prepared_case.target_path,"stripped_target_sha256":case.stripped_target_sha256,
            "symbolized_target":prepared_case.symbolized_path,
            "symbolized_target_sha256":case.symbolized_target_sha256,
            "original_compressed_database_sha256":case.compressed_database_sha256,
            "original_database_sha256":case.database_sha256,
            "builder_collector_source_sha256":case.collector_source_sha256,
            "builder_collector_support_sha256":case.collector_support_sha256,
            "builder_evaluator_binary_sha256":case.evaluator_binary_sha256,
            "library_object_sha256":case.library_object_sha256,
            "library_truth":serde_json::from_str::<Value>(&case.library_truth.0.to_json())
                .map_err(|error|error.to_string())?,
            "truth_functions":case.truth_functions,"full_twin_truth_functions":prepared_case.full_truth.0.len(),
            "full_twin_truth_sha256":digest(prepared_case.full_truth.to_json().as_bytes()),
            "builder_baseline_claim":case.baseline,"builder_per_library_claim":case.after,
            "load_image_equivalent_stripped_twin":true,"measurement":measurement
        }));
    }
    for prepared_case in &prepared {
        prepared_case.target.validate_backing_source().map_err(|error| error.to_string())?;
        prepared_case.symbolized.validate_backing_source().map_err(|error| error.to_string())?;
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let report = json!({
        "schema_version":1,"measurement":"phase2-1-collision-safe-signature-aggregate",
        "collector_source_sha256":digest(include_bytes!("signature_aggregate.rs")),
        "collector_support_sha256":digest(include_bytes!("signature_corpus_support/mod.rs")),
        "evaluator_binary_sha256":digest(&read_bounded(&executable,MAX_IMAGE_BYTES)?),
        "arch":measured.arch().to_string(),"scheme":measured.scheme(),
        "compressed_database_sha256":digest(&compressed),"compressed_database_bytes":compressed.len(),
        "database_sha256":digest(measured.to_json().as_bytes()),
        "database_signatures":measured.len(),"database_callee_keys":measured.callee_keys(),
        "database_inputs":databases.iter().map(|input|json!({
            "path":input.path,"compressed_sha256":input.sha256,"json_sha256":input.json_sha256,
            "compressed_bytes":input.compressed_bytes,"json_bytes":input.json_bytes
        })).collect::<Vec<_>>(),
        "composition":"SignatureDb::combine; not priority overlay or layered first-wins",
        "scored_reloaded_export":true,"reversed_order_export_equal":true,
        "rotated_order_export_equal":true,"gzip_round_trip_equal":true,
        "owned_recall_denominator":"exact original case library_truth count, including wrong names",
        "full_recall_denominator":"full canonical sized twin truth count, including wrong names",
        "matched_version_recall_gate":0.8,"target_executed":false,"cases":cases,"passed":passed,
        "limitations":[
            "Exact linked builds only, not near-miss or version identification; no default databases promoted.",
            "Builder reference/object hashes are recorded assertions, not independently rebuilt source proof.",
            "Full precision gold uses sized canonical symbols from a verified ELF twin, not unsized functions.",
            "Owned truth stays frozen; alias-set reconciliation is unsupported and canonical-name differences reject.",
            "Order checks cover forward/reverse/rotation exports, not every permutation.",
            "Output pairs use create_new with I/O-error cleanup, not crash-atomic multi-file publication."
        ]
    });
    let json = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    write_outputs(&arguments.output, &compressed, &arguments.report, &json)?;
    if !passed {
        return Err("aggregate gate failed; all case measurements and the aggregate artifact were retained".into());
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn truth(entries: &[(u64, &str)]) -> Truth {
        Truth(entries.iter().map(|(address, name)| (*address, (*name).to_owned())).collect())
    }

    #[test]
    fn other_library_correct_names_are_not_false_positives() {
        let owned = truth(&[(16, "inflate")]);
        let full = truth(&[(16, "inflate"), (32, "strlen"), (48, "main")]);
        let proposed = vec![(16, Some("inflate".into())), (32, Some("strlen".into()))];
        let (owned_report, full_report, passed) = grade(&proposed, &owned, &full);
        assert!(passed);
        assert_eq!(owned_report.correct, 1);
        assert_eq!((full_report.correct, full_report.wrong, full_report.spurious), (2, 0, 0));
        assert_eq!(full_report.precision, 1.0);
    }

    #[test]
    fn wrong_names_outside_owned_code_fail_even_when_owned_recall_is_perfect() {
        let owned = truth(&[(16, "inflate")]);
        let full = truth(&[(16, "inflate"), (32, "strlen")]);
        for (address, expected_wrong, expected_spurious) in [(32, 1, 0), (64, 0, 1)] {
            let proposed = vec![(16, Some("inflate".into())), (address, Some("memcpy".into()))];
            let (owned_report, full_report, passed) = grade(&proposed, &owned, &full);
            assert!(!passed);
            assert_eq!(owned_report.recall, 1.0);
            assert_eq!((full_report.wrong, full_report.spurious), (expected_wrong, expected_spurious));
        }
    }

    #[test]
    fn wrong_owned_names_remain_in_the_recall_denominator() {
        let owned = truth(&[(16, "inflate"), (32, "deflate")]);
        let proposed = vec![(16, Some("inflate".into())), (32, Some("wrong".into()))];
        let (report, _, passed) = grade(&proposed, &owned, &owned);
        assert!(!passed);
        assert_eq!(report.recall, 0.5);
        assert_eq!(report.correct + report.wrong + report.missed, owned.0.len());
    }

    #[test]
    fn association_is_hash_only_and_rejects_missing_or_reused_hashes() {
        let hash = "a".repeat(64);
        let index = index_hashes([(hash.clone(), PathBuf::from("not-a-guessed-case-name"))]).unwrap();
        assert_eq!(resolve_hash(&index, &hash).unwrap(), Path::new("not-a-guessed-case-name"));
        assert!(resolve_hash(&index, &"b".repeat(64)).is_err());
        assert!(index_hashes([(hash.clone(), PathBuf::from("one")), (hash, PathBuf::from("two"))]).is_err());
    }

    #[test]
    fn strict_truth_rejects_duplicates_noncanonical_addresses_and_empty_names() {
        for json in [r#"{"0x10":"a","0x10":"b"}"#, r#"{"0x010":"a"}"#, r#"{"0x10":""}"#, r#"{"16":"a"}"#] {
            assert!(serde_json::from_str::<StrictTruth>(json).is_err(), "{json}");
        }
        assert!(serde_json::from_str::<StrictTruth>(r#"{"0x10":"inflate"}"#).is_ok());
    }

    #[test]
    fn case_parser_requires_hash_bound_truth_but_does_not_trust_claimed_passed() {
        let hash = "a".repeat(64);
        let claimed = score(Vec::new(), &truth(&[(16, "inflate")]));
        let mut report = json!({
            "schema_version":1,"measurement":"phase2-1-library-signatures",
            "collector_source_sha256":hash,"collector_support_sha256":hash,"evaluator_binary_sha256":hash,
            "arch":"x86_64","scheme":2,"reference_sha256":"b".repeat(64),
            "symbolized_target_sha256":hash,"stripped_target_sha256":"c".repeat(64),
            "database_sha256":hash,"compressed_database_sha256":hash,
            "database_bytes":100,"compressed_database_bytes":80,
            "library_object_count":1,"library_object_sha256":[hash],
            "truth_functions":1,"library_truth":{"0x10":"inflate"},
            "load_image_equivalent_stripped_twin":true,"target_executed":false,
            "baseline":claimed,"after":claimed,"passed":true,"future_builder_field":42
        });
        assert!(parse_case(&serde_json::to_vec(&report).unwrap()).is_ok());
        report["truth_functions"] = json!(2);
        assert!(parse_case(&serde_json::to_vec(&report).unwrap()).is_err());
        report["truth_functions"] = json!(1);
        report["reference_sha256"] = json!("not-a-digest");
        assert!(parse_case(&serde_json::to_vec(&report).unwrap()).is_err());
        report["reference_sha256"] = json!("b".repeat(64));
        report.as_object_mut().unwrap().remove("collector_support_sha256");
        assert!(parse_case(&serde_json::to_vec(&report).unwrap()).is_err());
        report["collector_support_sha256"] = json!("a".repeat(64));
        report.as_object_mut().unwrap().remove("library_truth");
        assert!(parse_case(&serde_json::to_vec(&report).unwrap()).is_err());
    }

    #[test]
    fn actual_gzip_export_is_deterministic_and_order_independent_with_collisions() {
        let hash = "1".repeat(64);
        let make = |name| {
            let entries = BTreeMap::from([(hash.clone(), name)]);
            let json = json!({"arch":"x86_64","scheme":2,"entries":entries});
            let database = SignatureDb::from_json(&json.to_string()).unwrap();
            SignatureDb::from_gzip(&database.to_gzip().unwrap()).unwrap()
        };
        let first = make("inflate");
        let second = make("deflate");
        let third = make("inflate");
        let expected = export_combination([&first, &second, &third]).unwrap();
        for order in [
            [&first, &third, &second],
            [&second, &first, &third],
            [&second, &third, &first],
            [&third, &first, &second],
            [&third, &second, &first],
        ] {
            assert_eq!(expected, export_combination(order).unwrap());
        }
        let reloaded = SignatureDb::from_gzip(&expected).unwrap();
        assert_eq!(reloaded.to_gzip().unwrap(), expected);
        assert_eq!(reloaded.len(), 0);
    }
}
