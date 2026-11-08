//! `rampage-eval bundle` (docs/flywheel.md, "Bundle a promotion"): moves promoted flywheel entries into the
//! repository's bundled signature databases, through review.
//!
//! The bundled-database source for flywheel promotions is `crates/rampage-signatures/data/flywheel/libid.json`:
//! every bundled entry with its provenance id (the revert id it was promoted under) and its rows. The bundled assets
//! (`data/corpus-<arch>.json.gz` and their `.index.json`) carry those rows as their PAT namespace, under a
//! `flywheel-libid-<arch>` provenance profile; their hash entries are never touched.
//!
//! `bundle --from <pack>` merges the selected entries into the source, regenerates the assets from it, and reruns
//! the gate on the flywheel corpus with the regenerated databases against the repository's current ones (both in
//! place of the compiled-in databases, so nothing is rebuilt), that is against the bundled baseline: the entries were gated against an older baseline (and the arm), so they must pass again. When
//! the gate passes it writes a commit-ready change (the files in the working tree, and `change.patch`) and a summary
//! under `target/flywheel/bundle/<label>/`; it never commits. When it fails, the working tree is restored.
//! `bundle --remove <id>` takes an entry out the same way, requiring only that no false positive is added.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

use rampage_api::flywheel::{
    Corpus, Engine, FAMILY, GateConfig, NOVEL_SLICE, Paths, PromotedSet, Row, SliceDelta, Split, SplitEvaluation,
    compare,
};
use rampage_signatures::{BundledMetadata, BundledProfile, FLYWHEEL_PROFILE_PREFIX, PatternDb, SignatureDb};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The bundled source of flywheel promotions, relative to the repository root.
pub const SOURCE: &str = "crates/rampage-signatures/data/flywheel/libid.json";
const DATA: &str = "crates/rampage-signatures/data";
/// The architectures a bundled asset ships for.
const ARCHES: [&str; 4] = ["x86_64", "aarch64", "x86", "arm"];

#[derive(clap::Args)]
pub struct BundleArgs {
    /// A pack directory holding promoted flywheel entries (`entries.json`): the promoted pack, or one installed by
    /// `rampage packs import`.
    #[arg(long, conflicts_with_all = ["remove", "arm"], required_unless_present_any = ["remove", "arm"])]
    from: Option<PathBuf>,
    /// Bundle the deterministic arm for the corpus (its training rows, default operand wildcards) as one entry,
    /// gated like any other against the bundled baseline.
    #[arg(long, conflicts_with = "remove")]
    arm: bool,
    /// Bundle only these entries (revert ids, comma-separated or repeated); default: every entry of the pack.
    #[arg(long, value_delimiter = ',', requires = "from")]
    entries: Vec<String>,
    /// Remove the bundled entry with this provenance (revert) id.
    #[arg(long)]
    remove: Option<String>,
    /// The flywheel corpus the gate reruns on (target/flywheel/corpus/<version>).
    #[arg(long)]
    corpus: PathBuf,
    /// The repository whose bundled sources change (default: this build's).
    #[arg(long)]
    repository_root: Option<PathBuf>,
    /// The flywheel working directory (default: two levels above the corpus).
    #[arg(long)]
    flywheel_dir: Option<PathBuf>,
    /// A gate settings file; the gate's defaults otherwise.
    #[arg(long)]
    gate: Option<PathBuf>,
    /// Also require a held-out F1 gain on novel bodies (default: not required against the bundled baseline).
    #[arg(long)]
    require_novel_gain: Option<bool>,
    #[arg(long, default_value_t = 2)]
    workers: usize,
    /// Write the patch and summary only, restoring the working tree afterwards.
    #[arg(long)]
    patch_only: bool,
    /// A name for the output directory (default: bundle-<unix seconds>).
    #[arg(long)]
    label: Option<String>,
}

/// One bundled entry: a promotion's provenance id, where it came from, and its rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundledEntry {
    /// The revert id it was promoted under: its provenance id here too.
    pub id: String,
    pub family: String,
    pub candidate_hash: String,
    /// The pack it was bundled from (name and version).
    pub source_pack: String,
    pub corpus_version: String,
    /// What it was gated against when promoted: `arm:<hash>` or `bundled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_baseline: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposer_run: Option<String>,
    pub promoted_unix_ms: u64,
    /// The held-out change when it was promoted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_heldout_delta: Option<SliceDelta>,
    /// The bundle gate's held-out change against the bundled baseline (for the whole bundle it went in with).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundled_heldout_delta: Option<SliceDelta>,
    pub bundled_unix_ms: u64,
    /// The licence of the code the rows were made from (SPDX), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    pub rows: Vec<Row>,
}

/// The bundled source file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundledSource {
    pub schema_version: u32,
    pub family: String,
    pub entries: Vec<BundledEntry>,
}

impl BundledSource {
    /// The licences of the code every entry's rows were made from, `NOASSERTION` when any is unknown.
    pub fn license(&self) -> String {
        let mut licenses = std::collections::BTreeSet::new();
        for entry in &self.entries {
            match &entry.license {
                Some(license) => licenses.extend(license.split(" AND ").map(str::trim).map(str::to_owned)),
                None => return "NOASSERTION".to_owned(),
            }
        }
        if licenses.is_empty() {
            "NOASSERTION".to_owned()
        } else {
            licenses.into_iter().collect::<Vec<_>>().join(" AND ")
        }
    }

    pub fn rows(&self, arch: &str) -> Vec<Row> {
        self.entries.iter().flat_map(|entry| entry.rows.iter().filter(|row| row.arch == arch).cloned()).collect()
    }

    fn text(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map(|text| format!("{text}\n")).map_err(|error| error.to_string())
    }
}

/// The PAT namespace holding `rows` (all of one architecture), `None` when there are none.
fn patterns(arch: &str, rows: &[Row]) -> Result<Option<PatternDb>, String> {
    if rows.is_empty() {
        return Ok(None);
    }
    let mut text = String::new();
    for row in rows {
        text.push_str(&row.pat_line().map_err(|error| error.to_string())?);
        text.push('\n');
    }
    text.push_str("---\n");
    let arch = arch.parse()?;
    PatternDb::parse(arch, text.as_bytes()).map(Some).map_err(|error| format!("{arch} rows: {error}"))
}

/// One file the bundle changes: its path relative to the repository and its bytes before and after.
pub struct Change {
    pub path: String,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

/// The regenerated bundled assets and source: every file that differs, and the bundled databases before and after,
/// to measure.
pub struct Regenerated {
    pub changes: Vec<Change>,
    pub before: Vec<SignatureDb>,
    pub after: Vec<SignatureDb>,
    /// The architectures whose database changed.
    pub changed: std::collections::BTreeSet<String>,
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Regenerates the bundled assets of `repo` for the source `after`, given that they now hold `before`'s rows: an
/// asset whose PAT namespace is not exactly `before`'s rows is refused (someone else's patterns would be lost).
pub fn regenerate(repo: &Path, before: &BundledSource, after: &BundledSource) -> Result<Regenerated, String> {
    let mut changes = Vec::new();
    let (mut databases_before, mut databases) = (Vec::new(), Vec::new());
    let mut changed = std::collections::BTreeSet::new();
    for arch in ARCHES {
        let gz_path = repo.join(DATA).join(format!("corpus-{arch}.json.gz"));
        let index_path = repo.join(DATA).join(format!("corpus-{arch}.index.json"));
        if !gz_path.is_file() {
            continue;
        }
        let gz = read_bytes(&gz_path)?;
        let index = String::from_utf8(read_bytes(&index_path)?).map_err(|error| error.to_string())?;
        let mut metadata = BundledMetadata::parse(&index).map_err(|error| format!("{arch} index: {error}"))?;
        let mut database = metadata.load(&gz).map_err(|error| format!("{arch} asset: {error}"))?;
        databases_before.push(database.clone());
        let expected = patterns(arch, &before.rows(arch))?;
        let current = database.patterns().map(|patterns| patterns.records().to_vec());
        if current != expected.as_ref().map(|patterns| patterns.records().to_vec()) {
            return Err(format!(
                "{arch}: the bundled asset's PAT namespace is not exactly the rows {SOURCE} lists; refusing to \
                 regenerate it"
            ));
        }
        let rows = after.rows(arch);
        let wanted = patterns(arch, &rows)?;
        if wanted.as_ref().map(PatternDb::records) == expected.as_ref().map(PatternDb::records) {
            databases.push(database);
            continue;
        }
        database.set_patterns(wanted).map_err(|error| format!("{arch}: {error}"))?;
        changed.insert(arch.to_owned());
        let new_gz = database.to_gzip().map_err(|error| format!("{arch}: {error}"))?;
        let digest = {
            use sha2::Digest;
            rampage_arch::hex::bytes(&sha2::Sha256::digest(&new_gz))
        };
        metadata.gzip_sha256 = digest;
        metadata.compressed_bytes = new_gz.len();
        metadata.json_bytes = database.to_json().len();
        metadata.signatures = database.len();
        metadata.callee_keys = database.callee_keys();
        let profile_id = format!("{FLYWHEEL_PROFILE_PREFIX}{FAMILY}-{arch}");
        metadata.profiles.retain(|profile| profile.id != profile_id);
        if !rows.is_empty() {
            let ids: Vec<&str> = after
                .entries
                .iter()
                .filter(|entry| entry.rows.iter().any(|row| row.arch == arch))
                .map(|entry| entry.id.as_str())
                .collect();
            let corpora: std::collections::BTreeSet<&str> =
                after.entries.iter().map(|entry| entry.corpus_version.as_str()).collect();
            metadata.profiles.push(BundledProfile {
                id: profile_id,
                library: format!("flywheel {FAMILY} promotions"),
                version: format!("{} rows from {} entries", rows.len(), ids.len()),
                target: format!("{arch}-linux-musl"),
                compiler: "zig cc, Homebrew clang and Alpine gcc (flywheel corpus builds)".to_owned(),
                optimization: "O0, O2, Os and the distribution's".to_owned(),
                license: after.license(),
                source: format!("rampage flywheel promotions; provenance in {SOURCE}"),
                source_recipe: format!(
                    "entries {}; corpora {}; gated held out against the bundled baseline by rampage-eval bundle",
                    ids.join(", "),
                    corpora.into_iter().collect::<Vec<_>>().join(", ")
                ),
                archive_sha256: None,
                archive_identity_unavailable: Some(
                    "signature rows gated on a flywheel corpus, not a build of one source archive".to_owned(),
                ),
            });
        }
        let new_index = format!("{}\n", serde_json::to_string_pretty(&metadata).map_err(|error| error.to_string())?);
        let reloaded = BundledMetadata::parse(&new_index)
            .and_then(|metadata| metadata.load(&new_gz))
            .map_err(|error| format!("{arch}: the regenerated asset does not load: {error}"))?;
        databases.push(reloaded);
        changes.push(Change { path: format!("{DATA}/corpus-{arch}.json.gz"), before: gz, after: new_gz });
        changes.push(Change {
            path: format!("{DATA}/corpus-{arch}.index.json"),
            before: index.into_bytes(),
            after: new_index.into_bytes(),
        });
    }
    let source_before = before.text()?;
    let source_after = after.text()?;
    if source_before != source_after {
        let on_disk = read_bytes(&repo.join(SOURCE))?;
        changes.push(Change { path: SOURCE.to_owned(), before: on_disk, after: source_after.into_bytes() });
    }
    Ok(Regenerated { changes, before: databases_before, after: databases, changed })
}

/// Reads the bundled source.
pub fn load_source(repo: &Path) -> Result<BundledSource, String> {
    let path = repo.join(SOURCE);
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let source: BundledSource = serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    if source.schema_version != 1 || source.family != FAMILY {
        return Err(format!("{}: schema 1 of family {FAMILY} expected", path.display()));
    }
    Ok(source)
}

/// The source with the selected entries of the promoted pack in `pack` added.
pub fn merged(source: &BundledSource, pack: &Path, ids: &[String]) -> Result<(BundledSource, Vec<String>), String> {
    let manifest = rampage_api::packs::Packs::check(pack);
    if let Some(error) = &manifest.error {
        return Err(format!("{}: {error}", pack.display()));
    }
    let name = manifest.manifest.map(|manifest| format!("{} {}", manifest.name, manifest.version)).unwrap_or_default();
    let entries_path = pack.join(rampage_api::flywheel::ENTRIES_FILE);
    let text =
        std::fs::read_to_string(&entries_path).map_err(|error| format!("{}: {error}", entries_path.display()))?;
    let set: PromotedSet =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", entries_path.display()))?;
    if set.family != FAMILY {
        return Err(format!("{}: family {} (bundle takes {FAMILY})", entries_path.display(), set.family));
    }
    for id in ids {
        if !set.entries.iter().any(|entry| &entry.revert_id == id) {
            let known: Vec<&str> = set.entries.iter().map(|entry| entry.revert_id.as_str()).collect();
            return Err(format!("{id} is not an entry of {} (it has {})", pack.display(), known.join(", ")));
        }
    }
    let mut out = source.clone();
    let mut added = Vec::new();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    for entry in &set.entries {
        if !ids.is_empty() && !ids.contains(&entry.revert_id) {
            continue;
        }
        if !(entry.fast.passed && entry.heldout.passed) {
            return Err(format!("{} has no passing gate result; it cannot be bundled", entry.revert_id));
        }
        if let Some(existing) = out.entries.iter().find(|bundled| bundled.id == entry.revert_id) {
            if existing.candidate_hash != entry.candidate_hash {
                return Err(format!("{} is bundled already with other rows", entry.revert_id));
            }
            continue;
        }
        out.entries.push(BundledEntry {
            id: entry.revert_id.clone(),
            family: entry.family.clone(),
            candidate_hash: entry.candidate_hash.clone(),
            source_pack: name.clone(),
            corpus_version: entry.corpus_version.clone(),
            promoted_baseline: entry.baseline.clone(),
            proposer_run: entry.proposer_run.clone(),
            promoted_unix_ms: entry.promoted_unix_ms,
            promoted_heldout_delta: entry.heldout_deltas.get("all").cloned(),
            bundled_heldout_delta: None,
            bundled_unix_ms: now,
            license: None,
            rows: entry.rows.clone(),
        });
        added.push(entry.revert_id.clone());
    }
    Ok((out, added))
}

/// The source with the deterministic arm for `engine`'s corpus added as one entry, `arm-<rows hash>`. It replaces
/// an earlier arm entry, so one arm is bundled at a time.
pub fn with_arm(source: &BundledSource, engine: &Engine, gate: &GateConfig) -> Result<(BundledSource, String), String> {
    let arm = rampage_api::flywheel::arm(engine, gate.min_pattern_bytes).map_err(|error| error.to_string())?;
    let hash = arm.hash();
    let id = format!("arm-{}", &hash[..12]);
    if source.entries.iter().any(|entry| entry.id == id) {
        return Err(format!("{id} is bundled already; nothing to do"));
    }
    let mut out = source.clone();
    out.entries.retain(|entry| !entry.id.starts_with("arm-"));
    let classes: Vec<&str> = arm.wildcards.iter().map(|class| class.name()).collect();
    out.entries.push(BundledEntry {
        id: id.clone(),
        family: FAMILY.to_owned(),
        candidate_hash: hash,
        source_pack: format!("flywheel deterministic arm (wildcards: {})", classes.join(", ")),
        corpus_version: arm.corpus_version.clone(),
        promoted_baseline: Some("bundled".to_owned()),
        proposer_run: None,
        promoted_unix_ms: arm.generated_unix_ms,
        promoted_heldout_delta: None,
        bundled_heldout_delta: None,
        bundled_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64),
        license: Some(engine.corpus.license()),
        rows: arm.rows,
    });
    Ok((out, id))
}

/// The gate rerun: every split with the regenerated bundled databases against the repository's current ones (both
/// standing in for the compiled-in databases, so no rebuild is needed in between).
fn evaluate(engine: &Engine, regenerated: &Regenerated) -> Result<BTreeMap<Split, SplitEvaluation>, String> {
    let mut evaluations = BTreeMap::new();
    for split in [Split::Fast, Split::Train, Split::Negative, Split::Heldout] {
        let indices = engine.corpus.indices(split);
        let before = engine.propose_in(&indices, &[], Some(&regenerated.before)).map_err(|error| error.to_string())?;
        // Only binaries of an architecture whose database changed can be named differently.
        let changed: Vec<usize> =
            indices.iter().copied().filter(|&index| regenerated.changed.contains(&engine.binary(index).arch)).collect();
        let mut after = before.clone();
        let renamed = engine.propose_in(&changed, &[], Some(&regenerated.after)).map_err(|error| error.to_string())?;
        after.names.extend(renamed.names);
        evaluations.insert(split, compare(engine, split, &before, &after).map_err(|error| error.to_string())?);
    }
    Ok(evaluations)
}

fn delta_json(evaluation: &SplitEvaluation, slice: &str) -> Value {
    json!(evaluation.deltas().remove(slice))
}

pub fn run(args: BundleArgs) -> Result<ExitCode, String> {
    let started = Instant::now();
    let repo = args.repository_root.clone().unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let repo = std::fs::canonicalize(&repo).map_err(|error| format!("{}: {error}", repo.display()))?;
    let corpus = Corpus::open(&args.corpus).map_err(|error| error.to_string())?;
    let paths = match &args.flywheel_dir {
        Some(directory) => Paths::new(directory.clone()),
        None => Paths::for_corpus(&corpus.root).ok_or_else(|| {
            format!("{} is not inside a corpus/ directory; pass --flywheel-dir", corpus.root.display())
        })?,
    };
    let engine = Engine::new(corpus, paths.clone(), args.workers);
    let gate = match &args.gate {
        Some(path) => GateConfig::from_toml(&super::read(path)?).map_err(|error| error.to_string())?,
        None => GateConfig::default(),
    };
    let require_novel = args.require_novel_gain.or(gate.require_novel_gain).unwrap_or(false);

    let before = load_source(&repo)?;
    let (mut after, action, ids) = match (&args.from, &args.remove) {
        (None, None) if args.arm => {
            let (after, id) = with_arm(&before, &engine, &gate)?;
            (after, "add", vec![id])
        }
        (Some(pack), None) => {
            let (after, added) = merged(&before, pack, &args.entries)?;
            if added.is_empty() {
                return Err("every selected entry is bundled already; nothing to do".to_owned());
            }
            (after, "add", added)
        }
        (None, Some(id)) => {
            let mut after = before.clone();
            let position = after
                .entries
                .iter()
                .position(|entry| &entry.id == id)
                .ok_or_else(|| format!("no bundled entry has provenance id {id}"))?;
            after.entries.remove(position);
            (after, "remove", vec![id.clone()])
        }
        _ => return Err("give --from <pack>, --arm or --remove <id>".to_owned()),
    };

    // Measure first with the regenerated databases; the source records the result only once it passes.
    let mut regenerated = regenerate(&repo, &before, &after)?;
    let files: Vec<String> = regenerated.changes.iter().map(|change| change.path.clone()).collect();
    // The patch is `git diff` of these files: an uncommitted edit already in one would end up in it.
    let status = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["status", "--porcelain", "--"])
        .args(&files)
        .output()
        .map_err(|error| format!("git status: {error}"))?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err(format!(
            "{} has uncommitted changes in the files a bundle rewrites; commit or restore them first:\n{}",
            repo.display(),
            String::from_utf8_lossy(&status.stdout)
        ));
    }
    let evaluations = evaluate(&engine, &regenerated)?;
    let fast = gate.fast(&evaluations[&Split::Fast], &evaluations[&Split::Train], &evaluations[&Split::Negative]);
    let heldout_eval = &evaluations[&Split::Heldout];
    let (verdict, checks): (bool, Vec<Value>) = if action == "add" {
        let heldout = gate.heldout(heldout_eval, require_novel);
        let checks = fast.checks.iter().chain(&heldout.checks).map(|check| json!(check)).collect();
        (fast.passed && heldout.passed, checks)
    } else {
        // A removal takes rows out: it may lose names, but must not add a false one anywhere.
        let rise = |evaluation: &SplitEvaluation| {
            let (before, after) = evaluation.overall();
            after.fp() as i64 - before.fp() as i64
        };
        let checks: Vec<(String, i64)> = [Split::Train, Split::Negative, Split::Heldout]
            .iter()
            .map(|split| (format!("{}_fp_increase", split.name()), rise(&evaluations[split])))
            .collect();
        let passed = checks.iter().all(|(_, rise)| *rise <= 0);
        (passed, checks.iter().map(|(rule, rise)| json!({"rule": rule, "passed": *rise <= 0, "detail": format!("false positives {rise:+}")})).collect())
    };
    let heldout_all = heldout_eval.deltas().remove("all");
    for entry in &mut after.entries {
        if ids.contains(&entry.id) {
            entry.bundled_heldout_delta = heldout_all.clone();
        }
    }
    // The source now records the bundle's delta; the assets are unchanged by it.
    if let Some(change) = regenerated.changes.iter_mut().find(|change| change.path == SOURCE) {
        change.after = after.text()?.into_bytes();
    }

    let label = args.label.clone().unwrap_or_else(|| {
        format!(
            "bundle-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
        )
    });
    let out_dir = paths.root().join("bundle").join(&label);
    std::fs::create_dir_all(&out_dir).map_err(|error| format!("{}: {error}", out_dir.display()))?;
    if verdict {
        // Any failure between the first write and the patch restores every file.
        let written = (|| -> Result<Vec<u8>, String> {
            for change in &regenerated.changes {
                let path = repo.join(&change.path);
                std::fs::write(&path, &change.after).map_err(|error| format!("{}: {error}", path.display()))?;
            }
            let output = Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["diff", "--binary", "--"])
                .args(&files)
                .output()
                .map_err(|error| format!("git diff: {error}"))?;
            if !output.status.success() {
                return Err(format!("git diff failed: {}", String::from_utf8_lossy(&output.stderr)));
            }
            std::fs::write(out_dir.join("change.patch"), &output.stdout).map_err(|error| error.to_string())?;
            Ok(output.stdout)
        })();
        if args.patch_only || written.is_err() {
            restore(&repo, &regenerated.changes)?;
        }
        written?;
    }
    let summary = json!({
        "schema_version": 1,
        "action": action,
        "entries": ids,
        "passed": verdict,
        "checks": checks,
        "require_novel_gain": require_novel,
        "corpus_version": engine.corpus.version(),
        "repository": repo,
        "source": SOURCE,
        "files": regenerated.changes.iter().map(|change| json!({"path": change.path, "bytes_before": change.before.len(), "bytes_after": change.after.len()})).collect::<Vec<_>>(),
        "rows": after.entries.iter().map(|entry| entry.rows.len()).sum::<usize>(),
        "deltas": {
            "train": delta_json(&evaluations[&Split::Train], "all"),
            "negative": delta_json(&evaluations[&Split::Negative], "all"),
            "heldout": delta_json(heldout_eval, "all"),
            "heldout_novel": delta_json(heldout_eval, NOVEL_SLICE),
        },
        "applied_to_working_tree": verdict && !args.patch_only,
        "patch": if verdict { Some(out_dir.join("change.patch")) } else { None },
        "elapsed_ms": started.elapsed().as_millis() as u64,
    });
    let markdown = summary_markdown(&summary, &after, &ids);
    std::fs::write(
        out_dir.join("summary.json"),
        format!("{}\n", serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?),
    )
    .map_err(|error| error.to_string())?;
    std::fs::write(out_dir.join("summary.md"), &markdown).map_err(|error| error.to_string())?;
    println!("{markdown}");
    eprintln!("summary: {}", out_dir.join("summary.md").display());
    Ok(if verdict { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn restore(repo: &Path, changes: &[Change]) -> Result<(), String> {
    for change in changes {
        let path = repo.join(&change.path);
        std::fs::write(&path, &change.before).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(())
}

fn summary_markdown(summary: &Value, after: &BundledSource, ids: &[String]) -> String {
    let mut text = format!(
        "# Flywheel bundle: {} {}\n\nGate against the bundled baseline on corpus `{}`: **{}**.\n\n",
        summary["action"].as_str().unwrap_or("?"),
        ids.join(", "),
        summary["corpus_version"].as_str().unwrap_or("?"),
        if summary["passed"] == true { "passed" } else { "failed; nothing was changed" }
    );
    for check in summary["checks"].as_array().into_iter().flatten() {
        text.push_str(&format!(
            "- {} {}: {}\n",
            if check["passed"] == true { "ok" } else { "FAILED" },
            check["rule"].as_str().unwrap_or("?"),
            check["detail"].as_str().unwrap_or("")
        ));
    }
    text.push_str("\n| Split | dTP | dFP | dFN | dF1 |\n|---|---:|---:|---:|---:|\n");
    for (label, key) in [
        ("train", "train"),
        ("negative", "negative"),
        ("held out", "heldout"),
        ("held out, novel bodies", "heldout_novel"),
    ] {
        let delta = &summary["deltas"][key];
        text.push_str(&format!(
            "| {label} | {:+} | {:+} | {:+} | {:+.6} |\n",
            delta["tp"].as_i64().unwrap_or(0),
            delta["fp"].as_i64().unwrap_or(0),
            delta["fn"].as_i64().unwrap_or(0),
            delta["f1"].as_f64().unwrap_or(0.0)
        ));
    }
    text.push_str(&format!("\nBundled entries after this change ({} rows):\n", summary["rows"]));
    for entry in &after.entries {
        text.push_str(&format!(
            "- `{}` ({} rows, {}, corpus {}, promoted against {}): remove with `rampage-eval bundle --remove {}`\n",
            entry.id,
            entry.rows.len(),
            entry.source_pack,
            entry.corpus_version,
            entry.promoted_baseline.as_deref().unwrap_or("bundled"),
            entry.id
        ));
    }
    text.push_str("\nFiles:\n");
    for file in summary["files"].as_array().into_iter().flatten() {
        text.push_str(&format!("- `{}`\n", file["path"].as_str().unwrap_or("?")));
    }
    match summary["patch"].as_str() {
        Some(patch) if summary["applied_to_working_tree"] == true => text.push_str(&format!(
            "\nThe change is in the working tree, commit-ready (nothing was committed); the same change is in `{patch}`.\n"
        )),
        Some(patch) => text.push_str(&format!(
            "\nThe change is in `{patch}` (`git apply --binary` it); the working tree was restored.\n"
        )),
        None => {}
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_api::flywheel::{GateCheck, GateResult, PromotedEntry, sha256_file};

    fn workspace() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// A scratch repository holding copies of the bundled assets and the bundled source, committed to git so
    /// `bundle` can write its patch.
    fn scratch_repo(root: &Path) -> PathBuf {
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join(DATA).join("flywheel")).unwrap();
        for arch in ARCHES {
            for suffix in ["json.gz", "index.json"] {
                let name = format!("corpus-{arch}.{suffix}");
                std::fs::copy(workspace().join(DATA).join(&name), repo.join(DATA).join(&name)).unwrap();
            }
        }
        std::fs::copy(workspace().join(SOURCE), repo.join(SOURCE)).unwrap();
        git(&repo, &["init", "-q"]);
        commit(&repo, "assets");
        repo
    }

    fn git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .unwrap();
        assert!(status.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&status.stderr));
    }

    fn commit(repo: &Path, message: &str) {
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", message]);
    }

    fn passed(stage: &str) -> GateResult {
        GateResult {
            stage: stage.to_owned(),
            passed: true,
            checks: vec![GateCheck { rule: "heldout_f1_gain".to_owned(), passed: true, detail: String::new() }],
            failing_slices: vec![],
        }
    }

    fn entry(id: &str, rows: Vec<Row>) -> PromotedEntry {
        PromotedEntry {
            revert_id: id.to_owned(),
            family: FAMILY.to_owned(),
            candidate_id: format!("c-{id}"),
            candidate_hash: rampage_api::flywheel::rows_hash(&rows),
            driving_cases: rows.iter().filter_map(|row| row.source.clone()).collect(),
            rows,
            corpus_version: "synthetic-1".to_owned(),
            split: "heldout".to_owned(),
            baseline_hash: "b".to_owned(),
            build_id: "test".to_owned(),
            gate: GateConfig::default(),
            fast: passed("fast"),
            heldout: passed("heldout"),
            heldout_reference: BTreeMap::new(),
            heldout_candidate: BTreeMap::new(),
            heldout_deltas: BTreeMap::new(),
            proposer_run: Some("scripted/round-1".to_owned()),
            promoted_unix_ms: 1,
            baseline: Some("arm:0123456789ab".to_owned()),
            require_novel_gain: Some(true),
        }
    }

    /// The synthetic version-split corpus of tests/fixtures/flywheel in `root/corpus/synthetic-1`.
    fn synthetic_corpus(root: &Path) -> PathBuf {
        let fixtures = workspace().join("tests/fixtures/flywheel");
        let corpus = root.join("corpus").join("synthetic-1");
        std::fs::create_dir_all(&corpus).unwrap();
        for entry in std::fs::read_dir(&fixtures).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|extension| extension == "elf" || extension == "o") {
                std::fs::copy(&path, corpus.join(path.file_name().unwrap())).unwrap();
            }
        }
        let digest = |file: &str| sha256_file(&corpus.join(file)).unwrap();
        let mut binaries = Vec::new();
        for (version, split) in [("1", "train"), ("2", "heldout")] {
            for program in ["a", "b"] {
                let id = format!("v{version}-{program}");
                binaries.push(json!({
                    "id": id, "program": format!("minilib/{program}"), "library": "minilib",
                    "library_version": version, "split": split, "arch": "x86_64", "compiler": "zig", "opt": "O2",
                    "stripped": format!("{id}.elf"), "twin": format!("{id}.twin.elf"),
                    "program_object": format!("prog-{program}.o"), "library_object": format!("minilib-v{version}.o"),
                    "stripped_sha256": digest(&format!("{id}.elf")), "twin_sha256": digest(&format!("{id}.twin.elf")),
                    "program_object_sha256": digest(&format!("prog-{program}.o")),
                    "library_object_sha256": digest(&format!("minilib-v{version}.o")),
                }));
            }
        }
        binaries.push(json!({
            "id": "negative", "program": "owned/negative", "library": "owned", "library_version": "1",
            "split": "negative", "arch": "x86_64", "compiler": "zig", "opt": "O2",
            "stripped": "negative.elf", "twin": "negative.twin.elf", "program_object": "negative.o",
            "stripped_sha256": digest("negative.elf"), "twin_sha256": digest("negative.twin.elf"),
            "program_object_sha256": digest("negative.o"),
        }));
        let manifest = json!({
            "schema_version": 2, "family": "libid", "name": "synthetic", "version": "synthetic-1",
            "libraries": [{"name": "minilib", "license": "Apache-2.0", "role": "target"}],
            "split": {"rule": "version", "fast_programs_per_library": 1, "max_heldout_overlap": 1.0,
                      "refuse_heldout_overlap": 1.0},
            "binaries": binaries,
        });
        std::fs::write(corpus.join("manifest.json"), manifest.to_string()).unwrap();
        corpus
    }

    fn decoded(path: &Path) -> String {
        SignatureDb::from_gzip(&std::fs::read(path).unwrap()).unwrap().to_json()
    }

    #[test]
    fn regenerating_adds_rows_as_the_pat_namespace_and_removing_them_restores_the_assets() {
        let root = std::env::temp_dir().join(format!("rampage-bundle-regen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let repo = scratch_repo(&root);
        // Whatever the repository bundles already; the test adds one entry over it.
        let empty = load_source(&repo).unwrap();
        let row = Row {
            arch: "x86_64".to_owned(),
            name: "flywheel_test_function".to_owned(),
            library: Some("zlib".to_owned()),
            pattern: format!("554889e5{}5dc3", "4801c8".repeat(12)),
            length: None,
            source: None,
        };
        let mut added = empty.clone();
        added.entries.push(BundledEntry {
            id: "rv-test".to_owned(),
            family: FAMILY.to_owned(),
            candidate_hash: "h".to_owned(),
            source_pack: "test 0.1.0".to_owned(),
            corpus_version: "synthetic-1".to_owned(),
            promoted_baseline: None,
            proposer_run: None,
            promoted_unix_ms: 1,
            promoted_heldout_delta: None,
            bundled_heldout_delta: None,
            bundled_unix_ms: 2,
            license: Some("Zlib".to_owned()),
            rows: vec![row],
        });
        let gz = repo.join(DATA).join("corpus-x86_64.json.gz");
        let index = repo.join(DATA).join("corpus-x86_64.index.json");
        let (original_json, original_index) = (decoded(&gz), std::fs::read_to_string(&index).unwrap());
        let original_records = SignatureDb::from_gzip(&std::fs::read(&gz).unwrap()).unwrap().pat_records();

        let regenerated = regenerate(&repo, &empty, &added).unwrap();
        let paths: Vec<&str> = regenerated.changes.iter().map(|change| change.path.as_str()).collect();
        assert_eq!(paths.len(), 3, "the x86_64 asset, its index and the source: {paths:?}");
        let x86_64 = regenerated.after.iter().find(|database| database.arch().to_string() == "x86_64").unwrap();
        assert_eq!(x86_64.pat_records(), original_records + 1);
        for change in &regenerated.changes {
            std::fs::write(repo.join(&change.path), &change.after).unwrap();
        }
        let metadata = BundledMetadata::parse(&std::fs::read_to_string(&index).unwrap()).unwrap();
        let database = metadata.load(&std::fs::read(&gz).unwrap()).unwrap();
        assert_eq!(
            database.pat_records(),
            original_records + 1,
            "the regenerated asset loads as the bundled loader checks it"
        );
        assert!(metadata.profiles.iter().any(|profile| profile.id == "flywheel-libid-x86_64"));
        assert_eq!(load_source(&repo).unwrap(), added);

        // Regenerating again from a source that does not match the asset is refused.
        let error = regenerate(&repo, &empty, &added).err().unwrap();
        assert!(error.contains("not exactly the rows"), "{error}");

        // Removing the entry restores the database and its profiles exactly.
        let removed = regenerate(&repo, &added, &empty).unwrap();
        for change in &removed.changes {
            std::fs::write(repo.join(&change.path), &change.after).unwrap();
        }
        assert_eq!(decoded(&gz), original_json);
        let restored = std::fs::read_to_string(&index).unwrap();
        let original: Value = serde_json::from_str(&original_index).unwrap();
        let after: Value = serde_json::from_str(&restored).unwrap();
        assert_eq!(after["profiles"], original["profiles"]);
        assert_eq!(after["signatures"], original["signatures"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bundling_a_synthetic_pack_passes_the_gate_and_writes_a_patch_and_removing_it_reverts() {
        let root = std::env::temp_dir().join(format!("rampage-bundle-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let repo = scratch_repo(&root);
        let corpus = synthetic_corpus(&root);
        let flywheel = root.clone();

        // The pack: the deterministic arm's rows for minilib, as one promoted entry.
        let engine = Engine::new(Corpus::open(&corpus).unwrap(), Paths::new(flywheel.clone()), 1);
        let arm = rampage_api::flywheel::arm(&engine, 32).unwrap();
        assert!(!arm.rows.is_empty());
        let pack_paths = Paths::new(root.join("packs"));
        let set = PromotedSet {
            schema_version: 1,
            family: FAMILY.to_owned(),
            entries: vec![entry("rv-synthetic", arm.rows.clone())],
        };
        set.save(&pack_paths, "Apache-2.0").unwrap();
        let pack = pack_paths.promoted(FAMILY);

        // Merging refuses unknown entries and skips bundled ones. `empty` is what the repository bundles already.
        let empty = load_source(&repo).unwrap();
        let bundled = empty.entries.len();
        assert!(merged(&empty, &pack, &["rv-nope".to_owned()]).is_err());
        let (once, added) = merged(&empty, &pack, &[]).unwrap();
        assert_eq!(added, ["rv-synthetic"]);
        assert!(merged(&once, &pack, &[]).unwrap().1.is_empty());

        let args = |from: Option<PathBuf>, remove: Option<String>, label: &str, patch_only: bool| BundleArgs {
            from,
            arm: false,
            entries: vec![],
            remove,
            corpus: corpus.clone(),
            repository_root: Some(repo.clone()),
            flywheel_dir: Some(flywheel.clone()),
            gate: None,
            require_novel_gain: None,
            workers: 1,
            patch_only,
            label: Some(label.to_owned()),
        };
        let gz = repo.join(DATA).join("corpus-x86_64.json.gz");
        let original = decoded(&gz);

        // --patch-only: the gate passes, the patch is written and the tree is left as it was.
        run(args(Some(pack.clone()), None, "patch", true)).unwrap();
        let summary: Value =
            serde_json::from_str(&std::fs::read_to_string(flywheel.join("bundle/patch/summary.json")).unwrap())
                .unwrap();
        assert_eq!(summary["passed"], true, "{summary}");
        assert!(summary["deltas"]["heldout"]["tp"].as_i64().unwrap() > 0, "{summary}");
        assert_eq!(summary["deltas"]["heldout"]["fp"], 0);
        assert_eq!(summary["deltas"]["negative"]["fp"].as_i64().unwrap_or(0), 0, "no name on the negatives");
        let patch = std::fs::read_to_string(flywheel.join("bundle/patch/change.patch")).unwrap();
        assert!(patch.contains("GIT binary patch") && patch.contains(SOURCE), "{}", &patch[..patch.len().min(400)]);
        assert_eq!(decoded(&gz), original, "--patch-only restores the working tree");
        assert_eq!(load_source(&repo).unwrap().entries.len(), bundled);

        // The patch applies cleanly to the clean tree.
        let check = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["apply", "--check", "--binary"])
            .arg(flywheel.join("bundle/patch/change.patch"))
            .output()
            .unwrap();
        assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));

        // Without it, the change stays in the tree, commit-ready, with the gate's delta recorded per entry.
        run(args(Some(pack.clone()), None, "apply", false)).unwrap();
        let source = load_source(&repo).unwrap();
        assert_eq!(source.entries.len(), bundled + 1);
        let synthetic = source.entries.iter().find(|entry| entry.id == "rv-synthetic").unwrap();
        assert!(synthetic.bundled_heldout_delta.as_ref().is_some_and(|delta| delta.tp > 0));
        assert_ne!(decoded(&gz), original);

        // An uncommitted bundle blocks the next one: its patch would carry both.
        let dirty = run(args(None, Some("rv-synthetic".to_owned()), "dirty", false)).unwrap_err();
        assert!(dirty.contains("uncommitted changes"), "{dirty}");
        commit(&repo, "bundle rv-synthetic");

        // --remove takes it out by provenance id and restores the database.
        run(args(None, Some("rv-synthetic".to_owned()), "remove", false)).unwrap();
        assert_eq!(load_source(&repo).unwrap().entries.len(), bundled);
        assert_eq!(decoded(&gz), original);
        assert!(run(args(None, Some("rv-synthetic".to_owned()), "again", false)).is_err(), "nothing left to remove");
        let _ = std::fs::remove_dir_all(&root);
    }
}
