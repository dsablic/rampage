//! Read-only secondary-matcher experiment, deliberately separate from accepted corpus scorecards.
//!
//! Run with one JSON config path. Config fields are `library`, `reference_source`, `reference`,
//! `calibration`, `calibration_gold`, `heldout`, `heldout_gold`, and `owned_names` (source-selected names).
//! The three build paths must be distinct ELF artifacts; calibration/heldout must be stripped and their gold
//! copies must have identical code sections. Native code is inspected, never executed. Thresholds/margins
//! below are declared before held-out prediction. Failure to calibrate leaves all results candidate-only.
//! With a previously frozen calibration_snapshot, a second `--check-api` argument exercises only the native
//! read-only Project API against that database; it never opens calibration/heldout gold or changes policy.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};

use rampage_analysis::discover::{DiscoveredFunction, Program};
use rampage_loaders::{Binary, Format, SectionKind, SymbolKind};
use rampage_signatures::fuzzy;
use rampage_signatures::fuzzy::{
    CalibrationSample, CalleeProvenance, CandidateDisposition, CodeProjection, FuzzyDb, FuzzyFeatures,
    FuzzyMatchReport, FuzzyReference, KnownCallee, ReferenceProvenance,
};
use rampage_signatures::{MaskContext, SignatureDb, identify_program};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const THRESHOLDS: &[f64] = &[0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90];
const MARGINS: &[f64] = &[0.02, 0.05, 0.10, 0.15];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    library: String,
    reference_source: String,
    reference: PathBuf,
    calibration: PathBuf,
    calibration_gold: PathBuf,
    heldout: PathBuf,
    heldout_gold: PathBuf,
    owned_names: BTreeSet<String>,
    source_path: Option<PathBuf>,
    build_manifest: Option<PathBuf>,
    calibration_snapshot: Option<PathBuf>,
    prediction_snapshot: Option<PathBuf>,
}

struct Predicted {
    binary: Binary,
    program: Program,
    exact: BTreeMap<u64, String>,
    features: BTreeMap<u64, FuzzyFeatures>,
    extraction_rejections: BTreeMap<u64, String>,
}

#[derive(Default, Serialize)]
struct Metrics {
    owned_gold_functions: usize,
    discovered_owned_functions: usize,
    discovered_negative_functions: usize,
    exact_correct_owned: usize,
    exact_incorrect: usize,
    secondary_top_candidate_correct_owned_exact_misses: usize,
    secondary_top_candidate_incorrect_exact_misses: usize,
    secondary_eligible_correct_owned_exact_misses: usize,
    secondary_eligible_incorrect_exact_misses: usize,
    secondary_eligible_negative_exact_misses: usize,
    exact_misses_with_secondary_features: usize,
    candidate_top1_precision: Option<f64>,
    eligible_precision: Option<f64>,
    combined_correct_owned: usize,
    combined_owned_recall: Option<f64>,
    novel_secondary_top_candidate_correct_owned_exact_misses: usize,
    novel_secondary_eligible_correct_owned_exact_misses: usize,
}

#[derive(Serialize)]
struct Row {
    address: u64,
    exact: Option<String>,
    fuzzy: Option<FuzzyMatchReport>,
    extraction_rejection: Option<String>,
    /// Populated only after all held-out predictions have completed.
    evaluation_gold_names: BTreeSet<String>,
    /// Masked instruction identity against ALL discovered reference/calibration bodies, computed without labels.
    code_novel_to_prior_cohorts: Option<bool>,
}

#[derive(Serialize)]
struct Output {
    schema: u32,
    library: String,
    reference_source: String,
    reference_sha256: String,
    calibration_sha256: String,
    heldout_sha256: String,
    reference_executable_sha256: String,
    calibration_executable_sha256: String,
    heldout_executable_sha256: String,
    source_sha256: Option<String>,
    build_manifest_sha256: Option<String>,
    build_manifest: Option<String>,
    frozen_database_sha256: String,
    predictions_before_gold_sha256: String,
    declared_threshold_grid: &'static [f64],
    declared_margin_grid: &'static [f64],
    calibration: Option<fuzzy::CalibrationPolicy>,
    calibration_failure: Option<String>,
    reference_features: usize,
    reference_rejections: BTreeMap<String, String>,
    metrics: Metrics,
    rows: Vec<Row>,
    limitations: &'static [&'static str],
}

fn main() -> Result<()> {
    let config_path = std::env::args_os().nth(1).ok_or("expected a JSON config path")?;
    let config: Config = serde_json::from_slice(&std::fs::read(config_path)?)?;
    if std::env::args_os().nth(2).as_deref() == Some(std::ffi::OsStr::new("--check-api")) {
        return check_native_api(&config);
    }
    if config.owned_names.is_empty() {
        return Err("owned_names must be selected from source/reference labels before target evaluation".into());
    }
    let paths = [&config.reference, &config.calibration, &config.heldout];
    let canonical: BTreeSet<_> = paths.iter().map(std::fs::canonicalize).collect::<std::io::Result<_>>()?;
    let hashes: Vec<_> = paths.iter().map(|path| sha256(path)).collect::<Result<_>>()?;
    if canonical.len() != 3 || hashes.iter().collect::<BTreeSet<_>>().len() != 3 {
        return Err("reference/calibration/heldout must be distinct build artifacts".into());
    }
    let mut reference = Binary::open(&config.reference)?;
    require_elf(&reference)?;
    let reference_program = rampage_analysis::functions::analyze(&reference)?;
    let reference_code = rampage_api::fuzzy_code_identity(&reference, &reference_program)?;
    let mut prior_bodies = body_identities(&reference, &reference_program);
    let source_callees = rampage_analysis::functions::from_symbols(&reference)
        .into_iter()
        .map(|function| (function.address, function.name))
        .collect();
    reference.symbols.retain(|symbol| symbol.kind == SymbolKind::Function && config.owned_names.contains(&symbol.name));
    reference.exports.retain(|export| config.owned_names.contains(&export.name));
    let extents = reference_program.functions.iter().map(|function| (function.address, function.end())).collect();
    let exact_db = SignatureDb::from_binary_with_extents_and_callees(&reference, &extents, &source_callees);
    let known_reference = exact_names(&reference, &reference_program, &exact_db);
    let reference_callees = as_known_callees(&known_reference);
    let mut references = Vec::new();
    let mut reference_rejections = BTreeMap::new();
    for name in &config.owned_names {
        let Some(symbol) = reference.symbols.iter().find(|symbol| symbol.name == *name) else {
            reference_rejections.insert(name.clone(), "source-selected name absent in reference".to_owned());
            continue;
        };
        let Some(function) = reference_program.function_at(symbol.address) else {
            reference_rejections.insert(name.clone(), "reference not discovered".to_owned());
            continue;
        };
        let features = project_cfg(&reference, &reference_program, function)
            .and_then(|projection| Ok(fuzzy::extract_features(&reference, &projection, &reference_callees)?));
        match features {
            Ok(features) => references.push(FuzzyReference {
                name: name.clone(),
                features,
                provenance: ReferenceProvenance {
                    library: config.library.clone(),
                    source: config.reference_source.clone(),
                    cohort: reference_code.clone(),
                    image_sha256: Some(hashes[0].clone()),
                    executable_sha256: Some(reference_code.clone()),
                },
            }),
            Err(error) => {
                reference_rejections.insert(name.clone(), error.to_string());
            }
        }
    }
    let reference_features = references.len();
    let trained_names: BTreeSet<_> = references.iter().map(|reference| reference.name.clone()).collect();
    let mut db = FuzzyDb::new(references)?;

    // Feature extraction and predictions are complete before calibration labels are opened.
    let calibration = predict(&config.calibration, &exact_db)?;
    let calibration_code = rampage_api::fuzzy_code_identity(&calibration.binary, &calibration.program)?;
    if reference_code == calibration_code {
        return Err("reference/calibration executable code is identical despite file metadata differences".into());
    }
    prior_bodies.extend(body_identities(&calibration.binary, &calibration.program));
    let calibration_gold = gold(&config.calibration_gold, &calibration.binary)?;
    let samples: Vec<_> = calibration
        .features
        .iter()
        .filter(|(address, _)| !calibration.exact.contains_key(address))
        .map(|(address, features)| CalibrationSample {
            features,
            expected_reference_name: calibration_gold
                .get(address)
                .and_then(|names| names.iter().find(|name| trained_names.contains(*name)))
                .map(String::as_str),
        })
        .collect();
    let calibrated = db.calibrate(&calibration_code, &samples, THRESHOLDS, MARGINS);
    let (calibration_policy, calibration_failure) = match calibrated {
        Ok(policy) => (Some(policy), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let frozen_db = db.save_json()?;
    let frozen_database_sha256 = digest(&frozen_db);
    save_snapshot(config.calibration_snapshot.as_deref(), &frozen_db)?;

    let heldout = predict(&config.heldout, &exact_db)?;
    let heldout_code = rampage_api::fuzzy_code_identity(&heldout.binary, &heldout.program)?;
    if heldout_code == reference_code || heldout_code == calibration_code {
        return Err("heldout executable code duplicates an earlier cohort; not an independent code experiment".into());
    }
    let mut rows = Vec::new();
    for function in &heldout.program.functions {
        let exact = heldout.exact.get(&function.address).cloned();
        // Exact matches have priority; no secondary lookup or fallback can replace them.
        let report = if exact.is_none() {
            heldout
                .features
                .get(&function.address)
                .map(|features| db.candidates(features, &heldout_code, 16))
                .transpose()?
        } else {
            None
        };
        rows.push(Row {
            address: function.address,
            exact,
            fuzzy: report,
            extraction_rejection: heldout.extraction_rejections.get(&function.address).cloned(),
            evaluation_gold_names: BTreeSet::new(),
            code_novel_to_prior_cohorts: function
                .body(&heldout.binary)
                .and_then(|body| {
                    rampage_signatures::function_hash_in(
                        &heldout.binary.target(),
                        &MaskContext::from_binary(&heldout.binary),
                        body,
                        function.address,
                    )
                })
                .map(|hash| !prior_bodies.contains(&hash)),
        });
    }

    let frozen_predictions = serde_json::to_vec_pretty(&rows)?;
    let predictions_before_gold_sha256 = digest(&frozen_predictions);
    save_snapshot(config.prediction_snapshot.as_deref(), &frozen_predictions)?;
    // No held-out gold is opened until every exact/secondary prediction above has been frozen.
    let heldout_gold = gold(&config.heldout_gold, &heldout.binary)?;
    let metrics = evaluate(&mut rows, &heldout_gold, &config.owned_names);
    let output = Output {
        schema: 1,
        library: config.library,
        reference_source: config.reference_source,
        reference_sha256: hashes[0].clone(),
        calibration_sha256: hashes[1].clone(),
        heldout_sha256: hashes[2].clone(),
        reference_executable_sha256: reference_code,
        calibration_executable_sha256: calibration_code,
        heldout_executable_sha256: heldout_code,
        source_sha256: config.source_path.as_deref().map(sha256).transpose()?,
        build_manifest_sha256: config.build_manifest.as_deref().map(sha256).transpose()?,
        build_manifest: config.build_manifest.as_ref().map(std::fs::read_to_string).transpose()?,
        frozen_database_sha256,
        predictions_before_gold_sha256,
        declared_threshold_grid: THRESHOLDS,
        declared_margin_grid: MARGINS,
        calibration: calibration_policy,
        calibration_failure,
        reference_features,
        reference_rejections,
        metrics,
        rows,
        limitations: &[
            "Similarity is not probability or cryptographic identity; no names are persisted.",
            "Cohort threshold measurement is not a population false-positive guarantee.",
            "Source-selected names define ownership; unseen symbols/addresses count as negatives, not proof of malice.",
            "Discovery misses remain in the owned-function denominator; target gold sizes never enter lookup.",
            "No runtime execution or protected/commercial payload is required; ELF only in this driver.",
            "Novel gain excludes bodies already seen in either earlier cohort by existing masked instruction identity.",
        ],
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn require_elf(binary: &Binary) -> Result<()> {
    if binary.format != Format::Elf {
        return Err("this experiment requires ELF inputs".into());
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String> {
    Ok(digest(&std::fs::read(path)?))
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn save_snapshot(path: Option<&Path>, bytes: &[u8]) -> Result<()> {
    if let Some(path) = path {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
    }
    Ok(())
}

fn check_native_api(config: &Config) -> Result<()> {
    let path = config.calibration_snapshot.as_ref().ok_or("API check requires a frozen calibration snapshot")?;
    let database = FuzzyDb::load_json(&std::fs::read(path)?)?;
    let source = rampage_api::Project::new(Binary::open(&config.reference)?);
    let source_before = source.annotation_revision()?;
    let built = source.build_fuzzy_signatures(&rampage_api::FuzzyBuildRequest {
        provenance: ReferenceProvenance {
            library: config.library.clone(),
            source: config.reference_source.clone(),
            cohort: "API-reference".into(),
            image_sha256: None,
            executable_sha256: None,
        },
        owned_names: config.owned_names.clone(),
    })?;
    if built.references == 0 || !std::sync::Arc::ptr_eq(&source_before, &source.annotation_revision()?) {
        return Err("native API source build rejected all functions or mutated annotations".into());
    }
    let target = rampage_api::Project::new(Binary::open(&config.heldout)?);
    let target_before = target.annotation_revision()?;
    let program = rampage_analysis::functions::analyze(&target.binary)?;
    let exact = source.build_signatures();
    let suggestions = target.suggest_fuzzy_signatures(
        &database,
        Some(&exact),
        &rampage_api::FuzzySuggestRequest {
            cohort: rampage_api::fuzzy_code_identity(&target.binary, &program)?,
            addresses: program.functions.iter().map(|function| function.address).collect(),
            candidates_per_function: 16,
        },
    )?;
    let unchanged = std::sync::Arc::ptr_eq(&target_before, &target.annotation_revision()?);
    if !suggestions.read_only
        || !unchanged
        || !suggestions
            .suggestions
            .iter()
            .any(|row| matches!(row.status, rampage_api::FuzzySuggestionStatus::CandidateEvidence))
    {
        return Err("native API mutated annotations or returned no secondary evidence".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "source_references": built.references, "source_rejections": built.rejected,
            "source_annotations_unchanged": true, "target_annotations_unchanged": unchanged,
            "database_sha256": sha256(path)?, "gold_opened": false, "result": suggestions,
        }))?
    );
    Ok(())
}

fn body_identities(binary: &Binary, program: &Program) -> BTreeSet<rampage_signatures::FunctionHash> {
    let target = binary.target();
    let image = MaskContext::from_binary(binary);
    program
        .functions
        .iter()
        .filter_map(|function| {
            rampage_signatures::function_hash_in(&target, &image, function.body(binary)?, function.address)
        })
        .collect()
}

fn exact_names(binary: &Binary, program: &Program, database: &SignatureDb) -> BTreeMap<u64, String> {
    let bodies: Vec<_> =
        program.functions.iter().filter_map(|function| Some((function.address, function.body(binary)?))).collect();
    identify_program(&[database], &binary.target(), &MaskContext::from_binary(binary), &bodies)
        .into_iter()
        .map(|(address, name)| (address, name.to_owned()))
        .collect()
}

fn as_known_callees(names: &BTreeMap<u64, String>) -> BTreeMap<u64, KnownCallee> {
    names
        .iter()
        .map(|(address, name)| {
            (*address, KnownCallee { name: name.clone(), provenance: CalleeProvenance::ExactSignatureProposal })
        })
        .collect()
}

fn predict(path: &Path, database: &SignatureDb) -> Result<Predicted> {
    let binary = Binary::open(path)?;
    require_elf(&binary)?;
    if binary.symbols.iter().any(|symbol| symbol.kind == SymbolKind::Function) || !binary.exports.is_empty() {
        return Err("calibration/heldout inputs must have no function symbols or exports; supply separate gold".into());
    }
    let program = rampage_analysis::functions::analyze(&binary)?;
    let exact = exact_names(&binary, &program, database);
    let callees = as_known_callees(&exact);
    let mut features = BTreeMap::new();
    let mut extraction_rejections = BTreeMap::new();
    for function in &program.functions {
        let result = project_cfg(&binary, &program, function)
            .and_then(|projection| Ok(fuzzy::extract_features(&binary, &projection, &callees)?));
        match result {
            Ok(descriptor) => {
                features.insert(function.address, descriptor);
            }
            Err(error) => {
                extraction_rejections.insert(function.address, error.to_string());
            }
        }
    }
    Ok(Predicted { binary, program, exact, features, extraction_rejections })
}

/// Project actual production blocks and final-instruction successors, not a symbol-size linear sweep.
fn project_cfg(binary: &Binary, program: &Program, function: &DiscoveredFunction) -> Result<CodeProjection> {
    Ok(rampage_api::fuzzy_code_projection(binary, program, function)?)
}

fn gold(path: &Path, stripped: &Binary) -> Result<BTreeMap<u64, BTreeSet<String>>> {
    let gold = Binary::open(path)?;
    require_elf(&gold)?;
    if gold.arch != stripped.arch || gold.big_endian != stripped.big_endian {
        return Err("gold/stripped architecture mismatch".into());
    }
    let code: Vec<_> = stripped.sections.iter().filter(|section| section.kind == SectionKind::Code).collect();
    if code.is_empty() {
        return Err("cannot verify gold pairing without code sections".into());
    }
    for section in code {
        let Some(matching) = gold.sections.iter().find(|candidate| {
            candidate.kind == SectionKind::Code
                && candidate.address == section.address
                && candidate.size == section.size
        }) else {
            return Err("gold/stripped code section mismatch".into());
        };
        let left = stripped.section_file_bytes(section).ok_or("stripped code section lacks backing")?;
        let right = gold.section_file_bytes(matching).ok_or("gold code section lacks backing")?;
        if left != right {
            return Err("gold/stripped instruction bytes differ".into());
        }
    }
    let mut names: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for symbol in &gold.symbols {
        if symbol.kind == SymbolKind::Function && gold.is_code(symbol.address) {
            names.entry(symbol.address).or_default().insert(symbol.name.clone());
        }
    }
    if names.is_empty() {
        return Err("gold has no function labels".into());
    }
    Ok(names)
}

fn evaluate(rows: &mut [Row], gold: &BTreeMap<u64, BTreeSet<String>>, owned: &BTreeSet<String>) -> Metrics {
    let mut metrics = Metrics {
        owned_gold_functions: gold.values().filter(|names| !names.is_disjoint(owned)).count(),
        ..Metrics::default()
    };
    for row in rows {
        row.evaluation_gold_names = gold.get(&row.address).cloned().unwrap_or_default();
        let positive = !row.evaluation_gold_names.is_disjoint(owned);
        if positive {
            metrics.discovered_owned_functions += 1;
        } else {
            metrics.discovered_negative_functions += 1;
        }
        if let Some(exact) = &row.exact {
            if positive && row.evaluation_gold_names.contains(exact) {
                metrics.exact_correct_owned += 1;
            } else {
                metrics.exact_incorrect += 1;
            }
            continue;
        }
        let Some(report) = &row.fuzzy else { continue };
        metrics.exact_misses_with_secondary_features += 1;
        let Some(top) = report.candidates.first() else { continue };
        let correct = positive && row.evaluation_gold_names.contains(&top.name);
        // Tied/colliding candidates are not counted as top-1 answers just because lexical order picks a row.
        if !top.identical_feature_collision && top.margin_to_next_name > 0.0 {
            if correct {
                metrics.secondary_top_candidate_correct_owned_exact_misses += 1;
                if row.code_novel_to_prior_cohorts == Some(true) {
                    metrics.novel_secondary_top_candidate_correct_owned_exact_misses += 1;
                }
            } else {
                metrics.secondary_top_candidate_incorrect_exact_misses += 1;
            }
        }
        if matches!(top.disposition, CandidateDisposition::EligibleProposal) {
            if correct {
                metrics.secondary_eligible_correct_owned_exact_misses += 1;
                if row.code_novel_to_prior_cohorts == Some(true) {
                    metrics.novel_secondary_eligible_correct_owned_exact_misses += 1;
                }
            } else {
                metrics.secondary_eligible_incorrect_exact_misses += 1;
                if !positive {
                    metrics.secondary_eligible_negative_exact_misses += 1;
                }
            }
        }
    }
    metrics.candidate_top1_precision = fraction(
        metrics.secondary_top_candidate_correct_owned_exact_misses,
        metrics.secondary_top_candidate_correct_owned_exact_misses
            + metrics.secondary_top_candidate_incorrect_exact_misses,
    );
    metrics.eligible_precision = fraction(
        metrics.secondary_eligible_correct_owned_exact_misses,
        metrics.secondary_eligible_correct_owned_exact_misses + metrics.secondary_eligible_incorrect_exact_misses,
    );
    metrics.combined_correct_owned =
        metrics.exact_correct_owned + metrics.secondary_eligible_correct_owned_exact_misses;
    metrics.combined_owned_recall = fraction(metrics.combined_correct_owned, metrics.owned_gold_functions);
    metrics
}

fn fraction(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}
