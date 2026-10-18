use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use rampage_eval::{Report, Truth, discovered_extents, proposals, score};
use rampage_loaders::Binary;
use rampage_signatures::SignatureDb;
use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use serde_json::{Value, json};

mod signature_corpus_support;
use signature_corpus_support::{digest, verify_twin};
#[path = "signature_corpus_support/pdb_inputs.rs"]
mod pdb_inputs;
use pdb_inputs::{BoundPdb, PdbInputs};

#[cfg(test)]
#[allow(dead_code)]
mod fixture_support {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/pdb/support.rs"));
}

const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_REPORT_BYTES: u64 = 64 * 1024 * 1024;
const FROZEN_LEGACY_MUSL_GZIP_SHA256: [&str; 2] = [
    "a694f22852bee59d48d1110dcdd67ad28ae0139a77bf1550c258c9a04bb17693",
    "999f29784fc5a6b6b78500d9ac2c291a4f9d931214504e1cffcbaa0432992d58",
];

#[derive(Parser)]
struct Arguments {
    /// Original case databases; only the two exact frozen musl starters may lack a case association.
    #[arg(long = "database", required = true)]
    databases: Vec<PathBuf>,
    #[arg(long = "case", required = true)]
    cases: Vec<PathBuf>,
    #[arg(long = "target", required = true)]
    targets: Vec<PathBuf>,
    #[arg(long = "symbolized", required = true)]
    symbolized: Vec<PathBuf>,
    /// Hash-bound training images; required for PE cases, optional for historical ELF-only evaluation.
    #[arg(long = "reference")]
    references: Vec<PathBuf>,
    /// Explicit PDB sources, associated only by SHA-256 and checked PE identity; repeatable.
    #[arg(long = "pdb")]
    pdbs: Vec<PathBuf>,
    #[arg(long)]
    withhold_exact_fallbacks: bool,
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
    reference_pdb_sha256: Option<String>,
    target_pdb_sha256: Option<String>,
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
        || case.library_object_count > signature_corpus_support::MAX_LIBRARY_OBJECTS
        || case.library_object_count != case.library_object_sha256.len()
        || case.truth_functions == 0
        || case.truth_functions != case.library_truth.0.0.len()
        || case.reference_sha256 == case.symbolized_target_sha256
        || case.reference_sha256 == case.stripped_target_sha256
    {
        return Err("case is not a bounded, hash-bound signature_corpus builder report".into());
    }
    let arch: rampage_arch::Arch = case.arch.parse().map_err(|_| "invalid case architecture")?;
    match (&case.reference_pdb_sha256, &case.target_pdb_sha256) {
        (None, None) => (),
        (Some(reference), Some(target)) if is_digest(reference) && is_digest(target) => (),
        _ => return Err("case PDB hashes must be a paired set of canonical SHA-256 values".into()),
    }
    if case.arch != arch.to_string() {
        return Err("noncanonical case architecture".into());
    }
    Ok(case)
}

fn case_pdb_hash(case: &CaseReport, format: rampage_loaders::Format) -> Result<Option<&str>, String> {
    if (format == rampage_loaders::Format::Pe) != case.target_pdb_sha256.is_some() {
        return Err("PE cases require paired PDB hashes; ELF cases must not select PDB sources".into());
    }
    Ok(case.target_pdb_sha256.as_deref())
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

fn validate_database_provenance<'a>(
    databases: &[DatabaseInput],
    case_hashes: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, String> {
    let associated: BTreeSet<_> = case_hashes.into_iter().collect();
    let mut legacy_unattested = Vec::new();
    for input in databases {
        if FROZEN_LEGACY_MUSL_GZIP_SHA256.contains(&input.sha256.as_str()) {
            legacy_unattested.push(input.sha256.clone());
        } else if !associated.contains(input.sha256.as_str()) {
            return Err(format!("nonlegacy --database SHA-256 {} has no validated --case association", input.sha256));
        }
    }
    Ok(legacy_unattested)
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
        if !is_digest(&hash) {
            return Err("invalid image hash".into());
        }
        index.entry(hash).or_insert(path);
    }
    Ok(index)
}

fn resolve_hash<'a>(index: &'a BTreeMap<String, PathBuf>, hash: &str) -> Result<&'a Path, String> {
    index.get(hash).map(PathBuf::as_path).ok_or_else(|| format!("missing image with SHA-256 {hash}"))
}

fn reference_input_path(
    format: rampage_loaders::Format,
    references: Option<&BTreeMap<String, PathBuf>>,
    hash: &str,
) -> Result<Option<PathBuf>, String> {
    if format == rampage_loaders::Format::Pe && references.is_none() {
        return Err("PE cases require an actual --reference input and both identity-checked PDB sources".into());
    }
    references.map(|index| resolve_hash(index, hash)).transpose().map(|path| path.map(Path::to_owned))
}

struct ImageInputs {
    by_hash: BTreeMap<String, PathBuf>,
    evidence: Vec<(String, PathBuf)>,
}

impl ImageInputs {
    fn validate_current(&self) -> Result<(), String> {
        for (hash, path) in &self.evidence {
            if digest(&read_bounded(path, MAX_IMAGE_BYTES)?) != *hash {
                return Err(format!("{}: image input changed before publication", path.display()));
            }
        }
        Ok(())
    }
}

fn image_index(paths: &[PathBuf]) -> Result<ImageInputs, String> {
    let evidence = paths
        .iter()
        .map(|path| Ok((digest(&read_bounded(path, MAX_IMAGE_BYTES)?), path.clone())))
        .collect::<Result<Vec<_>, String>>()?;
    let by_hash = index_hashes(evidence.iter().cloned())?;
    Ok(ImageInputs { by_hash, evidence })
}

fn open_bound(path: &Path, expected_hash: &str) -> Result<Binary, String> {
    let bytes = read_bounded(path, MAX_IMAGE_BYTES)?;
    if (bytes.get(..4) != Some(b"\x7fELF") && bytes.get(..2) != Some(b"MZ")) || digest(&bytes) != expected_hash {
        return Err(format!("{}: expected a bounded hash-bound ELF or PE32+ x64 source", path.display()));
    }
    drop(bytes);
    let binary = Binary::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    binary.validate_backing_source().map_err(|error| error.to_string())?;
    let supported = binary.format == rampage_loaders::Format::Elf
        || (binary.format == rampage_loaders::Format::Pe
            && binary.arch == rampage_arch::Arch::X86_64
            && matches!(object::File::parse(binary.image_bytes()), Ok(object::File::Pe64(_))));
    if !supported
        || binary.image_bytes().len() as u64 > MAX_IMAGE_BYTES
        || digest(binary.image_bytes()) != expected_hash
    {
        return Err(format!("{}: expected the hash-bound ELF or PE32+ x64 image", path.display()));
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
    reference: Option<Binary>,
    reference_path: Option<PathBuf>,
    target_pdb: Option<BoundPdb>,
    reference_pdb: Option<BoundPdb>,
}

fn validate_held_out_split<'a>(cases: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>) -> Result<(), String> {
    let mut references = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for (reference, symbolized, stripped) in cases {
        references.insert(reference);
        targets.insert(symbolized);
        targets.insert(stripped);
    }
    if !references.is_disjoint(&targets) {
        return Err("training reference overlaps a held-out target in the aggregate corpus".into());
    }
    Ok(())
}

fn prepare_cases(
    paths: &[PathBuf],
    databases: &[DatabaseInput],
    targets: &BTreeMap<String, PathBuf>,
    symbolized: &BTreeMap<String, PathBuf>,
    references: Option<&BTreeMap<String, PathBuf>>,
    pdbs: &mut PdbInputs,
) -> Result<Vec<PreparedCase>, String> {
    let mut prepared = Vec::new();
    let mut report_bytes = 0;
    let mut used_targets = BTreeSet::new();
    let mut used_symbolized = BTreeSet::new();
    let mut used_references = BTreeSet::new();
    for path in paths {
        let bytes = read_bounded(path, MAX_REPORT_BYTES.min(MAX_TOTAL_REPORT_BYTES - report_bytes))?;
        report_bytes += bytes.len() as u64;
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
        used_targets.insert(case.stripped_target_sha256.clone());
        used_symbolized.insert(case.symbolized_target_sha256.clone());
        let target_path = resolve_hash(targets, &case.stripped_target_sha256)?.to_owned();
        let symbolized_path = resolve_hash(symbolized, &case.symbolized_target_sha256)?.to_owned();
        let target = open_bound(&target_path, &case.stripped_target_sha256)?;
        let mut symbolized = open_bound(&symbolized_path, &case.symbolized_target_sha256)?;
        if symbolized.format != target.format {
            return Err("symbolized and stripped target formats differ".into());
        }
        let reference_path = reference_input_path(symbolized.format, references, &case.reference_sha256)?;
        let target_pdb = case_pdb_hash(&case, symbolized.format)?
            .map(|hash| pdbs.attach(&mut symbolized, hash, Some(&case.library_truth.0)))
            .transpose()?;
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
        let mut reference = reference_path.as_ref().map(|path| open_bound(path, &case.reference_sha256)).transpose()?;
        let mut reference_pdb = None;
        if let Some(binary) = reference.as_mut() {
            if binary.format != symbolized.format {
                return Err("reference and target formats differ".into());
            }
            if let Some(hash) = case.reference_pdb_sha256.as_deref() {
                reference_pdb = Some(pdbs.attach(binary, hash, None)?);
            }
        }
        if let Some(binary) = &reference {
            if binary.arch.to_string() != case.arch {
                return Err("reference conflict source ARCH mismatch".into());
            }
            used_references.insert(case.reference_sha256.clone());
        }
        prepared.push(PreparedCase {
            path: path.clone(),
            report_sha256: digest(&bytes),
            case,
            target_path,
            symbolized_path,
            target,
            symbolized,
            full_truth,
            reference,
            reference_path,
            target_pdb,
            reference_pdb,
        });
    }
    if used_targets.len() != targets.len() || used_symbolized.len() != symbolized.len() {
        return Err("unused target or symbolized input; all associations must be exact SHA-256 matches".into());
    }
    if references.is_some_and(|inputs| inputs.len() != used_references.len()) {
        return Err("unused reference conflict input; all associations must be exact SHA-256 matches".into());
    }
    pdbs.validate_used()?;
    validate_held_out_split(prepared.iter().map(|item| {
        (
            item.case.reference_sha256.as_str(),
            item.case.symbolized_target_sha256.as_str(),
            item.case.stripped_target_sha256.as_str(),
        )
    }))?;
    prepared.sort_by(|left, right| left.report_sha256.cmp(&right.report_sha256));
    Ok(prepared)
}

fn filtered_export<'a>(
    databases: impl IntoIterator<Item = &'a SignatureDb>,
    references: &[SignatureDb],
    withhold_exact_fallbacks: bool,
) -> Result<(Vec<u8>, usize, usize), String> {
    let raw = export_combination(databases)?;
    let mut combined = SignatureDb::from_gzip(&raw).map_err(|error| error.to_string())?;
    let suppressed = combined.reject_reference_conflicts_from(references).map_err(|error| error.to_string())?;
    let withheld_exact = if withhold_exact_fallbacks { combined.withhold_exact_fallbacks() } else { 0 };
    Ok((combined.to_gzip().map_err(|error| error.to_string())?, suppressed, withheld_exact))
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
        || (!arguments.references.is_empty() && arguments.references.len() != arguments.cases.len())
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
    let references = image_index(&arguments.references)?;
    let mut pdbs = PdbInputs::new(&arguments.pdbs)?;
    let prepared = prepare_cases(
        &arguments.cases,
        &databases,
        &targets.by_hash,
        &symbolized.by_hash,
        (!arguments.references.is_empty()).then_some(&references.by_hash),
        &mut pdbs,
    )?;
    let legacy_unattested = validate_database_provenance(
        &databases,
        prepared.iter().map(|item| item.case.compressed_database_sha256.as_str()),
    )?;
    let mut reference_databases = Vec::new();
    let mut reference_evidence = Vec::new();
    for case in &prepared {
        if let Some(reference) = &case.reference {
            let extents = discovered_extents(reference).map_err(|error| error.to_string())?;
            let database = SignatureDb::from_binary_with_extents(reference, &extents);
            reference_evidence.push(json!({"path":case.reference_path,"sha256":case.case.reference_sha256,
                "database_sha256":digest(database.to_json().as_bytes())}));
            reference_databases.push(database);
        }
    }
    let (compressed, suppressed, withheld_exact) = filtered_export(
        databases.iter().map(|input| &input.database),
        &reference_databases,
        arguments.withhold_exact_fallbacks,
    )?;
    let (reversed, _, _) = filtered_export(
        databases.iter().rev().map(|input| &input.database),
        &reference_databases,
        arguments.withhold_exact_fallbacks,
    )?;
    let (rotated, _, _) = filtered_export(
        databases.iter().cycle().skip(1).take(databases.len()).map(|input| &input.database),
        &reference_databases,
        arguments.withhold_exact_fallbacks,
    )?;
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
        let mut case_evidence = json!({
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
        });
        case_evidence["input_format"] = json!(prepared_case.symbolized.format);
        case_evidence["training_reference_binding"] =
            json!(match (prepared_case.reference.is_some(), prepared_case.reference_pdb.is_some(),) {
                (true, true) => "actual_hash_bound_image_and_identity_checked_pdb",
                (true, false) => "actual_hash_bound_image",
                (false, _) => "unverified_case_assertion",
            });
        case_evidence["reference_pdb_sha256"] = json!(case.reference_pdb_sha256);
        case_evidence["target_pdb_sha256"] = json!(case.target_pdb_sha256);
        case_evidence["target_pdb_source"] =
            json!(prepared_case.target_pdb.as_ref().map(|pdb| json!({"path":pdb.path,"sha256":pdb.sha256})));
        case_evidence["reference_pdb_source"] =
            json!(prepared_case.reference_pdb.as_ref().map(|pdb| json!({"path":pdb.path,"sha256":pdb.sha256})));
        cases.push(case_evidence);
    }
    targets.validate_current()?;
    symbolized.validate_current()?;
    references.validate_current()?;
    pdbs.validate_current()?;
    for input in &databases {
        if digest(&read_bounded(&input.path, MAX_DATABASE_BYTES)?) != input.sha256 {
            return Err("database input changed before publication".into());
        }
    }
    for prepared_case in &prepared {
        if digest(&read_bounded(&prepared_case.path, MAX_REPORT_BYTES)?) != prepared_case.report_sha256 {
            return Err("case report changed before publication".into());
        }
        prepared_case.target.validate_backing_source().map_err(|error| error.to_string())?;
        prepared_case.symbolized.validate_backing_source().map_err(|error| error.to_string())?;
        if let Some(reference) = &prepared_case.reference {
            reference.validate_backing_source().map_err(|error| error.to_string())?;
        }
        for pdb in [&prepared_case.target_pdb, &prepared_case.reference_pdb].into_iter().flatten() {
            pdb.validate_current()?;
        }
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut report = json!({
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
            "Frozen legacy musl inputs lack recorded source archive and case/reference provenance.",
            "Full gold uses ELF sized symbols or all checked PE producer procedures, never unsized PUBLIC names.",
            "PE coverage is exact PE32+ x64 linked builds, not OS DLL implementation coverage.",
            "Owned truth stays frozen; alias-set reconciliation is unsupported and canonical-name differences reject.",
            "Order checks cover forward/reverse/rotation exports, not every permutation.",
            "Cases sharing an exact image SHA-256 remain separate measurements, not independent code diversity.",
            "Output pairs use create_new with I/O-error cleanup, not crash-atomic multi-file publication."
        ]
    });
    report["target_inputs"] = json!(targets.evidence);
    report["pdb_inputs"] = json!(pdbs.evidence);
    let actual_case_references_checked = prepared.iter().all(|item| item.reference.is_some());
    report["nonlegacy_database_case_associations_checked"] = json!(true);
    report["global_case_reference_hash_split_checked"] = json!(true);
    report["actual_case_training_reference_inputs_checked"] = json!(actual_case_references_checked);
    report["actual_training_reference_inputs_checked"] =
        json!(actual_case_references_checked && legacy_unattested.is_empty());
    report["legacy_unattested_input_sha256"] = json!(legacy_unattested);
    report["legacy_unattested_database_inputs"] = json!(
        legacy_unattested
            .iter()
            .map(|hash| json!({
                "compressed_sha256":hash,"source_archive_identity_unavailable":true,
                "case_reference_provenance_available":false,
                "limitation":concat!("Frozen public musl baseline; no recorded source archive identity, ",
                    "original case or training reference.")
            }))
            .collect::<Vec<_>>()
    );
    report["pdb_names_used_for_stripped_matching"] = json!(false);
    report["pdb_inputs_source_sha256"] = json!(digest(include_bytes!("signature_corpus_support/pdb_inputs.rs")));
    report["pe_strip_source_sha256"] = json!(digest(include_bytes!("../src/strip_pe.rs")));
    report["symbolized_inputs"] = json!(symbolized.evidence);
    report["reference_conflict_filter_applied"] = json!(!reference_databases.is_empty());
    report["reference_conflict_sources"] = json!(reference_evidence);
    report["reference_conflict_answer_keys_suppressed"] = json!(suppressed);
    report["raw_exact_fallback_answers_withheld"] = json!(arguments.withhold_exact_fallbacks);
    report["raw_exact_fallback_answer_keys_withheld"] = json!(withheld_exact);
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

    #[test]
    fn aggregate_split_rejects_cross_case_reference_target_swaps() {
        assert!(validate_held_out_split([("a", "b", "c"), ("b", "a", "d")]).is_err());
        assert!(validate_held_out_split([("a", "b", "c"), ("c", "d", "e")]).is_err());
        assert!(validate_held_out_split([("a", "b", "c"), ("d", "b", "c")]).is_ok());
    }

    #[test]
    fn hash_bound_admission_accepts_owned_elf_and_pe64_but_not_pdb_files_as_images() {
        for path in [fixture_support::fixture("fixture.exe"), fixture_support::fixture("../bin/eval-ref-x86_64.elf")] {
            let bytes = read_bounded(&path, MAX_IMAGE_BYTES).unwrap();
            let binary = open_bound(&path, &digest(&bytes)).unwrap();
            assert_eq!(binary.arch, rampage_arch::Arch::X86_64);
            assert!(open_bound(&path, &"0".repeat(64)).is_err());
        }
        let path = fixture_support::fixture("fixture.pdb");
        let bytes = read_bounded(&path, MAX_IMAGE_BYTES).unwrap();
        assert!(open_bound(&path, &digest(&bytes)).is_err());
    }

    fn database_input(path: &str, database: SignatureDb) -> DatabaseInput {
        let gzip = database.to_gzip().unwrap();
        let json = database.to_json();
        DatabaseInput {
            path: path.into(),
            sha256: digest(&gzip),
            json_sha256: digest(json.as_bytes()),
            compressed_bytes: gzip.len(),
            json_bytes: json.len(),
            database,
        }
    }

    #[test]
    fn extra_target_trained_database_cannot_bypass_case_provenance_or_pose_as_legacy_by_filename() {
        let reference = Binary::open(fixture_support::fixture("../bin/eval-ref-x86_64.elf")).unwrap();
        let target = Binary::open(fixture_support::fixture("../bin/eval-target-sym-x86_64.elf")).unwrap();
        let legitimate = database_input("case-db.json.gz", SignatureDb::from_binary(&reference));
        let extra = database_input("target-trained.json.gz", SignatureDb::from_binary(&target));
        assert_ne!(legitimate.sha256, extra.sha256);
        let case_hash = legitimate.sha256.clone();
        let mut inputs = vec![legitimate];
        assert!(validate_database_provenance(&inputs, [case_hash.as_str()]).unwrap().is_empty());
        let frozen = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rampage-signatures/data/musl-x86_64.json.gz");
        inputs.push(load_databases(&[frozen]).unwrap().pop().unwrap());
        let legacy = validate_database_provenance(&inputs, [case_hash.as_str()]).unwrap();
        assert_eq!(legacy, vec![inputs[1].sha256.clone()]);
        inputs.push(extra);
        assert!(validate_database_provenance(&inputs, [case_hash.as_str()]).is_err());
        inputs[2].path = "legacy-musl-x86_64.json.gz".into();
        assert!(validate_database_provenance(&inputs, [case_hash.as_str()]).is_err());
    }

    #[test]
    fn frozen_legacy_allowance_is_bound_to_both_original_gzip_assets() {
        for asset in ["musl-x86_64.json.gz", "musl-aarch64.json.gz"] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rampage-signatures/data").join(asset);
            let inputs = load_databases(&[path]).unwrap();
            assert_eq!(validate_database_provenance(&inputs, []).unwrap(), vec![inputs[0].sha256.clone()]);
        }
    }

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
    fn association_is_hash_only_and_allows_shared_content_without_guessing_names() {
        let hash = "a".repeat(64);
        let index = index_hashes([(hash.clone(), PathBuf::from("not-a-guessed-case-name"))]).unwrap();
        assert_eq!(resolve_hash(&index, &hash).unwrap(), Path::new("not-a-guessed-case-name"));
        assert!(resolve_hash(&index, &"b".repeat(64)).is_err());
        let shared =
            index_hashes([(hash.clone(), PathBuf::from("one")), (hash.clone(), PathBuf::from("two"))]).unwrap();
        assert_eq!(shared.len(), 1);
        assert_eq!(resolve_hash(&shared, &hash).unwrap(), Path::new("one"));
        assert!(index_hashes([("not-a-hash".into(), PathBuf::from("one"))]).is_err());
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
        let parsed = parse_case(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(case_pdb_hash(&parsed, rampage_loaders::Format::Elf).unwrap().is_none());
        assert!(case_pdb_hash(&parsed, rampage_loaders::Format::Pe).is_err());
        assert!(reference_input_path(rampage_loaders::Format::Elf, None, &parsed.reference_sha256).unwrap().is_none());
        report["reference_pdb_sha256"] = json!("d".repeat(64));
        assert!(parse_case(&serde_json::to_vec(&report).unwrap()).is_err());
        report["target_pdb_sha256"] = json!("e".repeat(64));
        let parsed = parse_case(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(case_pdb_hash(&parsed, rampage_loaders::Format::Pe).unwrap().is_some());
        assert!(case_pdb_hash(&parsed, rampage_loaders::Format::Elf).is_err());
        assert!(reference_input_path(rampage_loaders::Format::Pe, None, &parsed.reference_sha256).is_err());
        assert!(
            reference_input_path(rampage_loaders::Format::Pe, Some(&BTreeMap::new()), &parsed.reference_sha256)
                .is_err()
        );
        report["target_pdb_sha256"] = json!("not-a-digest");
        assert!(parse_case(&serde_json::to_vec(&report).unwrap()).is_err());
        report["reference_pdb_sha256"] = Value::Null;
        report["target_pdb_sha256"] = Value::Null;
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
