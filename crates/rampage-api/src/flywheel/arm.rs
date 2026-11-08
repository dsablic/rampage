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
//! Arm v2 also wildcards operand fields ([`OperandClass`]): each body's pattern with every byte of the chosen
//! classes wildcarded (by default all of them) is its widened pattern, so a row still matches when the next version
//! changes a constant, a structure offset or a stack slot. Bodies whose widened patterns agree form one widened
//! group, which becomes one row under the rules above. A widened group that is too short or long, ambiguous,
//! colliding or refused by the schema leaves its bodies to the next, narrower tier ([`tiers`]: relocations alone,
//! then exact rows), so with no classes the arm is v1.
//! The default is every class: choosing among class sets by held-out results would tune the baseline on the
//! held-out split.
//!
//! The arm is generated, not proposed: it reads only training and negative binaries, never the held-out split.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rampage_signatures::OperandClass;
use serde::{Deserialize, Serialize};

use super::candidate::{MAX_PATTERN_BYTES, Row, RowSource, format_pattern, rows_hash, write_pack};
use super::corpus::Split;
use super::engine::{Engine, RUNTIME, pattern_matches};
use super::{FlywheelError, build_id, read_bounded, sha256_text, write_atomic};

/// The arm's record inside its directory, beside the data pack holding its rows.
pub const ARM_FILE: &str = "arm.json";
/// Bumped when generation changes, so a stale arm is regenerated.
const ARM_FORMAT: &str = "flywheel-arm-v2";

/// The operand classes the arm wildcards unless told otherwise: all of them (see the module documentation).
pub const DEFAULT_WILDCARDS: [OperandClass; 7] = OperandClass::ALL;
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
    /// Groups tried at a widened tier (bodies agreeing outside the wildcarded operand bytes) that differ from an
    /// exact body.
    pub widened_groups: usize,
    /// Of those, groups that became one widened row.
    pub widened_rows: usize,
    /// Exact bodies those widened rows cover, each counted at the first tier that covers it.
    pub widened_bodies: usize,
    /// Widened groups that fell back to the next tier, by tier and reason.
    pub widening_fallbacks: BTreeMap<String, usize>,
    /// Rows by the tier that made them (`exact`, or the wildcarded classes joined by `+`).
    pub rows_by_tier: BTreeMap<String, usize>,
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
    /// The operand classes wildcarded (none for v1's exact rows).
    pub wildcards: Vec<OperandClass>,
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
pub fn directory(engine: &Engine, min_bytes: usize, wildcards: &[OperandClass]) -> PathBuf {
    let classes = wildcard_set(wildcards).iter().map(|class| class.name()).collect::<Vec<_>>().join(",");
    let key =
        sha256_text(&format!("{ARM_FORMAT}\0{}\0{}\0{min_bytes}\0{classes}", engine.corpus.identity(), build_id()));
    engine.paths.root().join("baseline").join(super::FAMILY).join(format!("{}-{}", engine.corpus.key(), &key[..12]))
}

/// The arm, loaded when one was generated for this corpus, build and minimum length, else generated and saved
/// (its record and a data pack of its rows).
pub fn load_or_generate(engine: &Engine, min_bytes: usize, wildcards: &[OperandClass]) -> Result<Arm, FlywheelError> {
    let wildcards = wildcard_set(wildcards);
    let directory = directory(engine, min_bytes, &wildcards);
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
                && arm.wildcards == wildcards
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
    let arm = generate(engine, min_bytes, &wildcards)?;
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

/// `wildcards` sorted and deduplicated, the form an arm records and keys on.
pub fn wildcard_set(wildcards: &[OperandClass]) -> Vec<OperandClass> {
    wildcards.iter().copied().collect::<BTreeSet<_>>().into_iter().collect()
}

/// `masked` with every byte whose class is in `wildcards` made a wildcard, or `masked` itself when the body's
/// architecture has no operand classes.
pub fn widen(
    masked: &[Option<u8>],
    classes: Option<&[Option<OperandClass>]>,
    wildcards: &[OperandClass],
) -> Vec<Option<u8>> {
    let Some(classes) = classes else { return masked.to_vec() };
    masked
        .iter()
        .enumerate()
        .map(|(position, byte)| match classes.get(position) {
            Some(Some(class)) if wildcards.contains(class) => None,
            _ => *byte,
        })
        .collect()
}

/// One training body under construction: a distinct (architecture, masked body).
struct Group {
    pattern: Vec<Option<u8>>,
    /// The pattern at each tier ([`tiers`]): wildcards wherever any member's form at that tier has one.
    tiers: Vec<Vec<Option<u8>>>,
    names: BTreeSet<String>,
    origins: BTreeSet<String>,
    example: (usize, u64),
}

/// The wildcard sets the arm tries, widest first: `wildcards`, then relocations alone, then none (exact rows).
/// A widened row the schema refuses (too few fixed bytes), or that is ambiguous or colliding, leaves its bodies to
/// the next tier rather than dropping them to exact rows.
pub fn tiers(wildcards: &[OperandClass]) -> Vec<Vec<OperandClass>> {
    let mut tiers = vec![wildcard_set(wildcards)];
    for tier in [vec![OperandClass::Relocation], Vec::new()] {
        let tier: Vec<OperandClass> = tier.into_iter().filter(|class| wildcards.contains(class)).collect();
        if !tiers.contains(&tier) {
            tiers.push(tier);
        }
    }
    tiers
}

/// A tier's name in reports: its classes, or `exact`.
fn tier_name(tier: &[OperandClass]) -> String {
    if tier.is_empty() {
        "exact".to_owned()
    } else {
        tier.iter().map(|class| class.name()).collect::<Vec<_>>().join("+")
    }
}

/// Why a group makes no row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dropped {
    TooShort,
    TooLong,
    Ambiguous,
    Colliding,
    Refused,
}

impl Dropped {
    fn name(self) -> &'static str {
        match self {
            Dropped::TooShort => "too_short",
            Dropped::TooLong => "too_long",
            Dropped::Ambiguous => "ambiguous",
            Dropped::Colliding => "colliding",
            Dropped::Refused => "refused",
        }
    }

    fn count(self, stats: &mut ArmStats) {
        *match self {
            Dropped::TooShort => &mut stats.too_short,
            Dropped::TooLong => &mut stats.too_long,
            Dropped::Ambiguous => &mut stats.ambiguous,
            Dropped::Colliding => &mut stats.colliding,
            Dropped::Refused => &mut stats.refused,
        } += 1;
    }
}

/// Makes rows from patterns under the rules in the module documentation.
struct RowMaker<'a> {
    engine: &'a Engine,
    functions: ByShape,
    arches: BTreeSet<String>,
    min_bytes: usize,
}

impl RowMaker<'_> {
    fn row(
        &self,
        arch: &str,
        pattern: &[Option<u8>],
        names: &BTreeSet<String>,
        origins: &BTreeSet<String>,
        example: (usize, u64),
    ) -> Result<Result<Row, Dropped>, FlywheelError> {
        let length = pattern.len();
        if length < self.min_bytes {
            return Ok(Err(Dropped::TooShort));
        }
        if length > MAX_PATTERN_BYTES {
            return Ok(Err(Dropped::TooLong));
        }
        if names.len() != 1 || origins.len() != 1 {
            return Ok(Err(Dropped::Ambiguous));
        }
        let name = names.first().expect("one name");
        let candidates = self.functions.get(&(arch.to_owned(), length)).map(Vec::as_slice).unwrap_or_default();
        for (index, start, truth) in candidates {
            if truth.as_deref() == Some(name.as_str()) {
                continue;
            }
            let loaded = self.engine.get(*index)?;
            if loaded.body(*start).is_some_and(|body| pattern_matches(pattern, body)) {
                return Ok(Err(Dropped::Colliding));
            }
        }
        let text = format_pattern(pattern);
        let row = Row {
            arch: arch.to_owned(),
            name: name.clone(),
            library: origins.first().cloned(),
            pattern: text.clone(),
            length: None,
            source: Some(RowSource {
                case: super::failures::case_id(arch, &text),
                binary: self.engine.binary(example.0).id.clone(),
                address: format!("{:#x}", example.1),
            }),
        };
        if row.validate(&self.arches, self.min_bytes).is_err() {
            return Ok(Err(Dropped::Refused));
        }
        Ok(Ok(row))
    }
}

/// Generates the arm from the training split's truth (see the module documentation).
pub fn generate(engine: &Engine, min_bytes: usize, wildcards: &[OperandClass]) -> Result<Arm, FlywheelError> {
    let started = std::time::Instant::now();
    let wildcards = wildcard_set(wildcards);
    let tiers = tiers(&wildcards);
    let train = engine.corpus.indices(Split::Train);
    let negative = engine.corpus.indices(Split::Negative);
    let mut stats = ArmStats::default();

    // Each training library body, by (architecture, masked pattern), with its pattern at every tier.
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
                Some(masked) => {
                    let classes = (!wildcards.is_empty())
                        .then(|| rampage_signatures::operand_classes(&target, &loaded.image, body, *address))
                        .flatten();
                    let widened: Vec<_> = tiers.iter().map(|tier| widen(&masked, classes.as_deref(), tier)).collect();
                    bodies.push((*address, masked, widened, truth.name.clone(), truth.origin.clone()))
                }
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
        for (address, masked, widened, name, origin) in bodies {
            let group = groups.entry((arch.clone(), format_pattern(&masked))).or_insert_with(|| Group {
                pattern: masked,
                tiers: widened.clone(),
                names: BTreeSet::new(),
                origins: BTreeSet::new(),
                example: (index, address),
            });
            for (tier, pattern) in group.tiers.iter_mut().zip(&widened) {
                for (slot, byte) in tier.iter_mut().zip(pattern) {
                    if slot != byte {
                        *slot = None;
                    }
                }
            }
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

    // Tier by tier, widest first: bodies agreeing at a tier form one group there, which becomes one row naming
    // every body it covers. A group whose bodies all have rows already is skipped; the exact tier counts drops.
    let maker = RowMaker { engine, functions, arches: engine.corpus.arches(), min_bytes };
    let mut rows = Vec::new();
    let mut covered: BTreeSet<(String, String)> = BTreeSet::new();
    // Widened patterns already tried: a narrower tier can produce the same pattern, with the same outcome.
    let mut tried: BTreeSet<(String, String)> = BTreeSet::new();
    for (level, tier) in tiers.iter().enumerate() {
        let exact = tier.is_empty();
        let mut agreeing: BTreeMap<(String, String), Vec<&(String, String)>> = BTreeMap::new();
        for (key, group) in &groups {
            agreeing.entry((key.0.clone(), format_pattern(&group.tiers[level]))).or_default().push(key);
        }
        for ((arch, text), members) in agreeing {
            if members.iter().all(|key| covered.contains(*key)) {
                continue;
            }
            let first = &groups[members[0]];
            let pattern = &first.tiers[level];
            let widens = !exact && (members.len() > 1 || *pattern != first.pattern);
            // Not widening, or a length no tier can row (widening keeps the length), or a pattern a wider tier
            // tried: leave it to the narrower tiers; the exact tier counts the drops.
            let rowable = (min_bytes..=MAX_PATTERN_BYTES).contains(&pattern.len());
            if !exact && (!widens || !rowable || !tried.insert((arch.clone(), text))) {
                continue;
            }
            let names: BTreeSet<String> = members.iter().flat_map(|key| groups[*key].names.iter().cloned()).collect();
            let origins: BTreeSet<String> =
                members.iter().flat_map(|key| groups[*key].origins.iter().cloned()).collect();
            if widens {
                stats.widened_groups += 1;
            }
            match maker.row(&arch, pattern, &names, &origins, first.example)? {
                Ok(row) => {
                    if widens {
                        stats.widened_rows += 1;
                        stats.widened_bodies += members.iter().filter(|key| !covered.contains(**key)).count();
                    }
                    *stats.rows_by_tier.entry(tier_name(tier)).or_default() += 1;
                    covered.extend(members.into_iter().cloned());
                    rows.push(row);
                }
                Err(dropped) if exact => dropped.count(&mut stats),
                Err(dropped) => {
                    *stats.widening_fallbacks.entry(format!("{}: {}", tier_name(tier), dropped.name())).or_default() +=
                        1
                }
            }
        }
    }
    stats.rows = rows.len();
    Ok(Arm {
        schema_version: 2,
        family: super::FAMILY.to_owned(),
        corpus_version: engine.corpus.version().to_owned(),
        corpus_identity: engine.corpus.identity().to_owned(),
        build_id: build_id().to_owned(),
        min_pattern_bytes: min_bytes,
        wildcards,
        generated_unix_ms: super::now_ms(),
        elapsed_ms: started.elapsed().as_millis() as u64,
        stats,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widen_wildcards_only_the_chosen_classes_and_keeps_masked_wildcards() {
        use OperandClass::*;
        let masked = [Some(0x48), Some(0x8b), Some(0x47), Some(0x10), Some(0xe8), None, Some(0x00)];
        let classes = [None, None, None, Some(Disp8), None, Some(Relocation), Some(Relocation)];
        assert_eq!(
            widen(&masked, Some(&classes), &[Disp8, Relocation]),
            [Some(0x48), Some(0x8b), Some(0x47), None, Some(0xe8), None, None]
        );
        assert_eq!(widen(&masked, Some(&classes), &[Imm8]), masked, "no byte of an unchosen class changes");
        assert_eq!(widen(&masked, None, &[Disp8]), masked, "an unclassified architecture keeps the masked body");
    }

    #[test]
    fn wildcard_sets_are_sorted_and_deduplicated() {
        use OperandClass::*;
        assert_eq!(wildcard_set(&[Imm8, Relocation, Imm8]), [Relocation, Imm8]);
        assert_eq!(wildcard_set(&DEFAULT_WILDCARDS), OperandClass::ALL);
    }

    #[test]
    fn tiers_narrow_to_relocations_then_exact_rows() {
        use OperandClass::*;
        assert_eq!(tiers(&OperandClass::ALL), [OperandClass::ALL.to_vec(), vec![Relocation], vec![]]);
        assert_eq!(tiers(&[Relocation]), [vec![Relocation], vec![]]);
        assert_eq!(tiers(&[Imm8, Disp8]), [vec![Disp8, Imm8], vec![]], "relocations only when chosen");
        assert_eq!(tiers(&[]), [Vec::<OperandClass>::new()], "no classes: v1's exact rows");
    }
}
