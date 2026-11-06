//! The deterministic baseline arm: every signature row a plain generator can make from the training split's truth,
//! with no AI. It is the bar a proposer must clear (docs/flywheel.md, "The deterministic arm").
//!
//! The arm takes each target-library truth function of the training split and its body as scheme 2 masks it (the
//! `masked_bytes` a `corpus_failures` group shows, and the form a proposer's `case` row takes), and keeps one row per
//! distinct (architecture, masked body) under the same rules a proposed row meets:
//! - the pattern is at least the gate's `min_pattern_bytes` and at most `MAX_PATTERN_BYTES`, and passes the row
//!   schema (enough fixed bytes to ever answer);
//! - collisions are handled as the signature builder handles them (`SignatureDb::add`): a body seen with more than
//!   one name is ambiguous and never answers. The arm drops it, which for its own answers is the same.
//! - a body that also matches a function with another name, or none, anywhere in the training or negative
//!   binaries is dropped: a proposed row matching one would fail the fast gate.
//!
//! The arm is generated, not proposed: it reads only training and negative binaries, never the held-out split.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::candidate::{MAX_PATTERN_BYTES, Row, RowSource, format_pattern, rows_hash, write_pack};
use super::corpus::Split;
use super::engine::{Engine, RUNTIME, pattern_matches};
use super::{FlywheelError, build_id, read_bounded, sha256_text, write_atomic};

/// The arm's record inside its directory, beside the data pack holding its rows.
pub const ARM_FILE: &str = "arm.json";
/// Bumped when generation changes, so a stale arm is regenerated.
const ARM_FORMAT: &str = "flywheel-arm-v1";
const MAX_ARM_BYTES: u64 = 256 * 1024 * 1024;

/// What the generator saw and why bodies were left out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmStats {
    /// Target-library truth functions in the training split.
    pub training_functions: usize,
    /// Of those, discovery never found them, so no row can name them.
    pub undiscovered: usize,
    /// Bodies too small or uniform for the confidence gate.
    pub below_gate: usize,
    /// Distinct (architecture, masked body) groups.
    pub bodies: usize,
    pub too_short: usize,
    pub too_long: usize,
    /// Groups seen with more than one truth name.
    pub ambiguous: usize,
    /// Groups whose pattern also matches a training or negative function with another name or none.
    pub colliding: usize,
    /// Groups the row schema refuses (too few fixed bytes).
    pub refused: usize,
    pub rows: usize,
}

/// The arm for one corpus, build and minimum pattern length.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arm {
    pub schema_version: u32,
    pub family: String,
    pub corpus_version: String,
    pub corpus_identity: String,
    pub build_id: String,
    pub min_pattern_bytes: usize,
    pub generated_unix_ms: u64,
    pub elapsed_ms: u64,
    pub stats: ArmStats,
    pub rows: Vec<Row>,
}

impl Arm {
    /// The SHA-256 of the arm's rows, part of every evaluation's baseline key when the arm is the baseline.
    pub fn hash(&self) -> String {
        rows_hash(&self.rows)
    }
}

/// The directory holding the arm for `engine`'s corpus, this build and `min_bytes`: `baseline/libid/<key>/`.
pub fn directory(engine: &Engine, min_bytes: usize) -> PathBuf {
    let key = sha256_text(&format!("{ARM_FORMAT}\0{}\0{}\0{min_bytes}", engine.corpus.identity(), build_id()));
    engine.paths.root().join("baseline").join(super::FAMILY).join(format!("{}-{}", engine.corpus.key(), &key[..12]))
}

/// The arm, loaded when one was generated for this corpus, build and minimum length, else generated and saved
/// (its record and a data pack of its rows).
pub fn load_or_generate(engine: &Engine, min_bytes: usize) -> Result<Arm, FlywheelError> {
    let directory = directory(engine, min_bytes);
    let path = directory.join(ARM_FILE);
    let saved = || -> Result<Option<Arm>, FlywheelError> {
        if !path.is_file() {
            return Ok(None);
        }
        let text = read_bounded(&path, MAX_ARM_BYTES)?;
        Ok(serde_json::from_str::<Arm>(&text).ok().filter(|arm| {
            arm.corpus_identity == engine.corpus.identity()
                && arm.build_id == build_id()
                && arm.min_pattern_bytes == min_bytes
        }))
    };
    if let Some(arm) = saved()? {
        return Ok(arm);
    }
    // Another server may have generated it while this one waited for the lock.
    let _lock = super::FileLock::acquire(&directory.with_extension("lock"))?;
    if let Some(arm) = saved()? {
        return Ok(arm);
    }
    let arm = generate(engine, min_bytes)?;
    write_pack(
        &directory,
        "flywheel-arm-libid",
        &format!("0.0.0+{}", &arm.hash()[..12]),
        &engine.corpus.license(),
        &format!("rampage flywheel deterministic arm (corpus {}, training split)", engine.corpus.version()),
        "Every signature row a deterministic generator makes from the flywheel corpus's training truth: the \
         baseline an AI proposer must beat. Reference only.",
        &arm.rows,
    )?;
    write_atomic(&path, serde_json::to_string(&arm).map_err(super::FlywheelError::json)?.as_bytes())?;
    Ok(arm)
}

/// Discovered functions by (architecture, length): binary index, start and truth name (none outside the truth).
type ByShape = BTreeMap<(String, usize), Vec<(usize, u64, Option<String>)>>;

/// One training body under construction.
struct Group {
    pattern: Vec<Option<u8>>,
    names: BTreeSet<String>,
    origins: BTreeSet<String>,
    example: (usize, u64),
}

/// Generates the arm from the training split's truth (see the module documentation).
pub fn generate(engine: &Engine, min_bytes: usize) -> Result<Arm, FlywheelError> {
    let started = std::time::Instant::now();
    let train = engine.corpus.indices(Split::Train);
    let negative = engine.corpus.indices(Split::Negative);
    let mut stats = ArmStats::default();

    // Each training library body, by (architecture, masked pattern).
    let found = engine.parallel(&train, |index| {
        let loaded = engine.get(index)?;
        let target = loaded.binary.target();
        let mut bodies = Vec::new();
        let (mut functions, mut undiscovered, mut below_gate) = (0, 0, 0);
        for (address, truth) in &loaded.truth {
            if truth.origin == RUNTIME {
                continue;
            }
            functions += 1;
            let Some(body) = loaded.body(*address).filter(|_| loaded.discovered(*address)) else {
                undiscovered += 1;
                continue;
            };
            match rampage_signatures::masked_body_in(&target, &loaded.image, body, *address) {
                Some(masked) => bodies.push((*address, masked, truth.name.clone(), truth.origin.clone())),
                None => below_gate += 1,
            }
        }
        Ok((index, bodies, functions, undiscovered, below_gate))
    })?;
    let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
    for (index, bodies, functions, undiscovered, below_gate) in found {
        stats.training_functions += functions;
        stats.undiscovered += undiscovered;
        stats.below_gate += below_gate;
        let arch = engine.binary(index).arch.clone();
        for (address, masked, name, origin) in bodies {
            let group = groups.entry((arch.clone(), format_pattern(&masked))).or_insert_with(|| Group {
                pattern: masked,
                names: BTreeSet::new(),
                origins: BTreeSet::new(),
                example: (index, address),
            });
            group.names.insert(name);
            group.origins.insert(origin);
        }
    }
    stats.bodies = groups.len();

    // Every discovered function of the training and negative binaries, by (architecture, length), with its truth
    // name (none for program code, negatives and anything outside the truth), for the collision check.
    let mut functions: ByShape = BTreeMap::new();
    for &index in train.iter().chain(&negative) {
        let loaded = engine.get(index)?;
        let negative = engine.binary(index).split == super::corpus::Role::Negative;
        for &(start, end) in &loaded.functions {
            let Some(length) = end.checked_sub(start) else { continue };
            let name = if negative { None } else { loaded.truth.get(&start).map(|truth| truth.name.clone()) };
            functions
                .entry((engine.binary(index).arch.clone(), length as usize))
                .or_default()
                .push((index, start, name));
        }
    }

    let arches = engine.corpus.arches();
    let mut rows = Vec::new();
    for ((arch, _), group) in groups {
        let length = group.pattern.len();
        if length < min_bytes {
            stats.too_short += 1;
            continue;
        }
        if length > MAX_PATTERN_BYTES {
            stats.too_long += 1;
            continue;
        }
        if group.names.len() != 1 || group.origins.len() != 1 {
            stats.ambiguous += 1;
            continue;
        }
        let name = group.names.into_iter().next().expect("one name");
        let candidates = functions.get(&(arch.clone(), length)).map(Vec::as_slice).unwrap_or_default();
        let mut colliding = false;
        for (index, start, truth) in candidates {
            if truth.as_deref() == Some(name.as_str()) {
                continue;
            }
            let loaded = engine.get(*index)?;
            if loaded.body(*start).is_some_and(|body| pattern_matches(&group.pattern, body)) {
                colliding = true;
                break;
            }
        }
        if colliding {
            stats.colliding += 1;
            continue;
        }
        let pattern = format_pattern(&group.pattern);
        let row = Row {
            arch: arch.clone(),
            name,
            library: group.origins.into_iter().next(),
            pattern: pattern.clone(),
            length: None,
            source: Some(RowSource {
                case: super::failures::case_id(&arch, &pattern),
                binary: engine.binary(group.example.0).id.clone(),
                address: format!("{:#x}", group.example.1),
            }),
        };
        if row.validate(&arches, min_bytes).is_err() {
            stats.refused += 1;
            continue;
        }
        rows.push(row);
    }
    stats.rows = rows.len();
    Ok(Arm {
        schema_version: 1,
        family: super::FAMILY.to_owned(),
        corpus_version: engine.corpus.version().to_owned(),
        corpus_identity: engine.corpus.identity().to_owned(),
        build_id: build_id().to_owned(),
        min_pattern_bytes: min_bytes,
        generated_unix_ms: super::now_ms(),
        elapsed_ms: started.elapsed().as_millis() as u64,
        stats,
        rows,
    })
}
