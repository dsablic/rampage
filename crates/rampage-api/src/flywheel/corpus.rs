//! A built flywheel corpus: its manifest, the split each binary belongs to, the fast slice, the corpus identity
//! and the slice keys every binary is reported under.
//!
//! The split is by library version. Every training binary links an older version of a target library and every
//! held-out binary its current version, so a held-out gain needs a signature that carries across versions, not
//! one that recognises the same build again. Negative binaries link unrelated libraries or none: no target
//! signature may name anything in them. A split by program is not used: the programs of one configuration share
//! the same library build, so holding out a program holds out nothing the training split lacks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{FlywheelError, hex, sha256_file, sha256_text};

/// The manifest file at the root of a built corpus.
pub const MANIFEST: &str = "manifest.json";
/// The manifest schema this version reads.
pub const SCHEMA_VERSION: u32 = 2;
/// Largest manifest read.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
/// Most binaries one corpus may list.
const MAX_BINARIES: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusManifest {
    pub schema_version: u32,
    /// The heuristic family the corpus measures; `libid` is the only one so far.
    pub family: String,
    pub name: String,
    /// The content address of the corpus.
    pub version: String,
    #[serde(default)]
    pub toolchains: serde_json::Value,
    #[serde(default)]
    pub libraries: Vec<serde_json::Value>,
    pub split: SplitConfig,
    pub binaries: Vec<CorpusBinary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitConfig {
    /// How binaries are assigned to splits; `version` (each binary's `split` field) is the only rule.
    pub rule: String,
    #[serde(default)]
    pub unit: String,
    /// Training programs per target library in the fast slice.
    pub fast_programs_per_library: usize,
    /// The share of held-out library bodies (masked) that may also occur in training before a server warns, loudly,
    /// that held-out gains are mostly recognition of code training already holds.
    #[serde(default = "default_overlap")]
    pub max_heldout_overlap: f64,
    /// The share above which a server refuses the corpus: the held-out split is then essentially the training
    /// build again.
    #[serde(default = "default_refused_overlap")]
    pub refuse_heldout_overlap: f64,
    /// What the final split holds, when the corpus has one (descriptive).
    #[serde(default, rename = "final", skip_serializing_if = "String::is_empty")]
    pub final_split: String,
}

fn default_overlap() -> f64 {
    0.5
}

fn default_refused_overlap() -> f64 {
    0.95
}

/// Which part of the corpus a binary belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Train,
    Heldout,
    Negative,
    /// The final split: library versions no design decision, gate or report reads, measured only by an explicit,
    /// ledgered `flywheel-eval --split final` (docs/flywheel.md, "The final split").
    Final,
}

/// One stripped binary of the corpus with its symbolized twin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusBinary {
    pub id: String,
    /// The program (driver source) the binary was built from.
    pub program: String,
    /// The library the program links: a target, a negative library, or `owned` for none.
    pub library: String,
    /// The library's version.
    pub library_version: String,
    /// The split the binary belongs to.
    pub split: Role,
    pub arch: String,
    pub compiler: String,
    pub opt: String,
    /// The evaluated binary, relative to the corpus root.
    pub stripped: String,
    /// The same image with its symbol table: the truth source.
    pub twin: String,
    /// The program's own object: its functions are left out of the truth.
    #[serde(default)]
    pub program_object: Option<String>,
    /// The library's objects linked into one relocatable: names it defines are tagged with the library.
    #[serde(default)]
    pub library_object: Option<String>,
    /// Names of the program's own functions, for a corpus without program objects.
    #[serde(default)]
    pub program_names: Vec<String>,
    pub stripped_sha256: String,
    pub twin_sha256: String,
    #[serde(default)]
    pub program_object_sha256: Option<String>,
    #[serde(default)]
    pub library_object_sha256: Option<String>,
}

impl CorpusBinary {
    /// The gated slices this binary is reported under, `all` first. `program_library` is the library the
    /// program links; the origin of each function is reported separately (`origin:` slices).
    pub fn slices(&self) -> Vec<String> {
        vec![
            "all".to_owned(),
            format!("arch:{}", self.arch),
            format!("compiler:{}", self.compiler),
            format!("opt:{}", self.opt),
            format!("program_library:{}", self.library),
            format!("cell:{}/{}/{}/{}", self.arch, self.compiler, self.opt, self.library),
        ]
    }

    /// The architecture, compiler and optimisation level, as failures name where a body was seen.
    pub fn configuration(&self) -> String {
        format!("{}/{}/{}", self.arch, self.compiler, self.opt)
    }
}

/// Which part of the corpus an evaluation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Split {
    /// Every training binary: the older library versions.
    Train,
    /// The current library versions: never shown to a proposer, only measured.
    Heldout,
    /// A fixed small subset of the training binaries, for quick feedback with cases.
    Fast,
    /// Binaries without any target library: every name a target signature gives there is false.
    Negative,
    /// Untouched library versions (often another toolchain's builds), for claims rather than decisions.
    Final,
}

impl Split {
    pub fn name(self) -> &'static str {
        match self {
            Split::Train => "train",
            Split::Heldout => "heldout",
            Split::Fast => "fast",
            Split::Negative => "negative",
            Split::Final => "final",
        }
    }
}

impl std::str::FromStr for Split {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "train" => Ok(Split::Train),
            "heldout" => Ok(Split::Heldout),
            "fast" => Ok(Split::Fast),
            "negative" => Ok(Split::Negative),
            "final" => Ok(Split::Final),
            other => Err(format!("unknown split `{other}` (train, heldout, fast, negative or final)")),
        }
    }
}

/// A loaded corpus with its split.
#[derive(Debug, Clone)]
pub struct Corpus {
    pub root: PathBuf,
    pub manifest: CorpusManifest,
    /// Fast-slice programs (all of them training programs).
    fast: BTreeSet<String>,
    identity: String,
}

impl Corpus {
    /// Loads the corpus at `root` and checks every file it lists against its recorded SHA-256, so a binary
    /// changed after the build cannot be measured under the old corpus identity.
    pub fn open(root: &Path) -> Result<Corpus, FlywheelError> {
        let corpus = Corpus::open_unchecked(root)?;
        for binary in &corpus.manifest.binaries {
            let files = [
                (Some(&binary.stripped), Some(&binary.stripped_sha256)),
                (Some(&binary.twin), Some(&binary.twin_sha256)),
                (binary.program_object.as_ref(), binary.program_object_sha256.as_ref()),
                (binary.library_object.as_ref(), binary.library_object_sha256.as_ref()),
            ];
            for (path, digest) in files {
                let (Some(path), Some(digest)) = (path, digest) else { continue };
                let actual = sha256_file(&corpus.path(path))?;
                if &actual != digest {
                    return Err(FlywheelError::Corpus(format!(
                        "{}: SHA-256 {actual} differs from the manifest's {digest}; rebuild the corpus",
                        corpus.path(path).display()
                    )));
                }
            }
        }
        Ok(corpus)
    }

    /// Loads the manifest without hashing the files.
    pub fn open_unchecked(root: &Path) -> Result<Corpus, FlywheelError> {
        let root = root.canonicalize().map_err(|error| FlywheelError::io(root, error))?;
        let path = root.join(MANIFEST);
        let text = super::read_bounded(&path, MAX_MANIFEST_BYTES)?;
        let manifest: CorpusManifest = serde_json::from_str(&text)
            .map_err(|error| FlywheelError::Corpus(format!("{}: {error}", path.display())))?;
        Corpus::from_manifest(root, manifest)
    }

    pub fn from_manifest(root: PathBuf, manifest: CorpusManifest) -> Result<Corpus, FlywheelError> {
        let invalid = |message: String| Err(FlywheelError::Corpus(message));
        if manifest.schema_version != SCHEMA_VERSION {
            return invalid(format!(
                "manifest schema {} (this version reads {SCHEMA_VERSION}); rebuild the corpus",
                manifest.schema_version
            ));
        }
        if manifest.family != "libid" {
            return invalid(format!("family `{}` (this version evaluates libid)", manifest.family));
        }
        if manifest.version.is_empty()
            || !manifest.version.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return invalid(format!("corpus version {:?} is not a plain identifier", manifest.version));
        }
        if manifest.split.rule != "version" {
            return invalid(format!("split rule `{}` (this version splits by library version)", manifest.split.rule));
        }
        let overlaps = [manifest.split.max_heldout_overlap, manifest.split.refuse_heldout_overlap];
        if !overlaps.iter().all(|share| (0.0..=1.0).contains(share)) {
            return invalid("split.max_heldout_overlap and refuse_heldout_overlap must be in [0, 1]".to_owned());
        }
        if manifest.binaries.is_empty() || manifest.binaries.len() > MAX_BINARIES {
            return invalid(format!("a corpus lists 1 to {MAX_BINARIES} binaries"));
        }
        let mut ids = BTreeSet::new();
        let mut versions: BTreeMap<(&str, Role), BTreeSet<&str>> = BTreeMap::new();
        for binary in &manifest.binaries {
            if !ids.insert(binary.id.as_str()) {
                return invalid(format!("binary id {} is listed twice", binary.id));
            }
            let paths = [
                Some(&binary.stripped),
                Some(&binary.twin),
                binary.program_object.as_ref(),
                binary.library_object.as_ref(),
            ];
            for path in paths.into_iter().flatten() {
                if Path::new(path).is_absolute() || Path::new(path).components().any(|part| part.as_os_str() == "..") {
                    return invalid(format!("{}: path {path} must stay inside the corpus", binary.id));
                }
            }
            if binary.arch.parse::<rampage_arch::Arch>().is_err() {
                return invalid(format!("{}: unknown architecture {}", binary.id, binary.arch));
            }
            versions.entry((binary.library.as_str(), binary.split)).or_default().insert(&binary.library_version);
        }
        // A version split holds out versions: one library version on both sides would hold out nothing. The final
        // split holds out versions from the held-out split too, so a decision read there says nothing about it.
        for ((library, role), held) in &versions {
            let others: &[(Role, &str)] = match role {
                Role::Heldout => &[(Role::Train, "training")],
                Role::Final => &[(Role::Train, "training"), (Role::Heldout, "held-out")],
                _ => continue,
            };
            let name = if *role == Role::Final { "final" } else { "held-out" };
            for (other, other_name) in others {
                if let Some(seen) = versions.get(&(*library, *other))
                    && let Some(shared) = held.intersection(seen).next()
                {
                    return invalid(format!("{library} {shared} is in both the {other_name} and the {name} split"));
                }
            }
        }
        let fast = fast_programs(&manifest);
        let identity = identity(&manifest);
        Ok(Corpus { root, manifest, fast, identity })
    }

    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    /// A SHA-256 over the version, the split configuration and every binary's role and file hashes: the corpus as
    /// the gate sees it, so a manifest edited without rebuilding cannot reuse another corpus's results.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The version and the start of the identity, for directory names.
    pub fn key(&self) -> String {
        format!("{}-{}", self.version(), &self.identity[..12])
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// Whether `binary` belongs to `split`.
    pub fn in_split(&self, binary: &CorpusBinary, split: Split) -> bool {
        match split {
            Split::Heldout => binary.split == Role::Heldout,
            Split::Train => binary.split == Role::Train,
            Split::Negative => binary.split == Role::Negative,
            Split::Final => binary.split == Role::Final,
            Split::Fast => binary.split == Role::Train && self.fast.contains(&binary.program),
        }
    }

    /// The indices of the binaries in `split`, in manifest order.
    pub fn indices(&self, split: Split) -> Vec<usize> {
        let binaries = self.manifest.binaries.iter().enumerate();
        binaries.filter(|(_, binary)| self.in_split(binary, split)).map(|(index, _)| index).collect()
    }

    pub fn fast_programs(&self) -> &BTreeSet<String> {
        &self.fast
    }

    /// The architectures the corpus holds.
    /// Final binaries are left out, so an architecture only the final split holds is never offered or accepted.
    pub fn arches(&self) -> BTreeSet<String> {
        self.manifest
            .binaries
            .iter()
            .filter(|binary| binary.split != Role::Final)
            .map(|binary| binary.arch.clone())
            .collect()
    }

    /// The SPDX expression covering the target libraries, for packs made from them.
    pub fn license(&self) -> String {
        let licenses: BTreeSet<&str> = self
            .manifest
            .libraries
            .iter()
            .filter(|library| {
                library.get("role").and_then(serde_json::Value::as_str).is_none_or(|role| role == "target")
            })
            .filter_map(|library| library.get("license").and_then(serde_json::Value::as_str))
            .collect();
        if licenses.is_empty() {
            "NOASSERTION".to_owned()
        } else {
            licenses.into_iter().collect::<Vec<_>>().join(" AND ")
        }
    }
}

/// The fast slice: within each library's training programs, ordered by SHA-256 of the corpus version and the
/// program name, the first `fast_programs_per_library`.
fn fast_programs(manifest: &CorpusManifest) -> BTreeSet<String> {
    let mut by_library: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for binary in manifest.binaries.iter().filter(|binary| binary.split == Role::Train) {
        by_library.entry(binary.library.as_str()).or_default().insert(binary.program.as_str());
    }
    let mut fast = BTreeSet::new();
    for programs in by_library.values() {
        let mut ordered: Vec<(String, &str)> =
            programs.iter().map(|program| (split_key(&manifest.version, program), *program)).collect();
        ordered.sort();
        for (_, program) in ordered.into_iter().take(manifest.split.fast_programs_per_library) {
            fast.insert(program.to_owned());
        }
    }
    fast
}

fn split_key(version: &str, program: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rampage flywheel split\0");
    hasher.update(version.as_bytes());
    hasher.update([0]);
    hasher.update(program.as_bytes());
    hex(&hasher.finalize())
}

fn identity(manifest: &CorpusManifest) -> String {
    let mut binaries: Vec<String> = manifest
        .binaries
        .iter()
        .map(|binary| {
            format!(
                "{}|{:?}|{}|{}|{}|{}",
                binary.id,
                binary.split,
                binary.stripped_sha256,
                binary.twin_sha256,
                binary.program_object_sha256.as_deref().unwrap_or(""),
                binary.library_object_sha256.as_deref().unwrap_or("")
            )
        })
        .collect();
    binaries.sort();
    let split = serde_json::to_string(&manifest.split).unwrap_or_default();
    sha256_text(&format!("{}\0{split}\0{}", manifest.version, binaries.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str) -> CorpusManifest {
        let mut binaries = Vec::new();
        for (library, versions) in [
            ("zlib", [("1.2", Role::Train), ("1.3", Role::Heldout)]),
            ("lz4", [("1.9", Role::Train), ("1.10", Role::Heldout)]),
        ] {
            for (library_version, split) in versions {
                for program in 0..4 {
                    binaries.push(CorpusBinary {
                        id: format!("{library}-{library_version}-p{program}"),
                        program: format!("{library}/p{program}"),
                        library: library.to_owned(),
                        library_version: library_version.to_owned(),
                        split,
                        arch: "x86_64".to_owned(),
                        compiler: "zig".to_owned(),
                        opt: "O2".to_owned(),
                        stripped: "a".to_owned(),
                        twin: "b".to_owned(),
                        program_object: None,
                        library_object: None,
                        program_names: vec![],
                        stripped_sha256: format!("{library}{library_version}{program}"),
                        twin_sha256: String::new(),
                        program_object_sha256: None,
                        library_object_sha256: None,
                    });
                }
            }
        }
        CorpusManifest {
            schema_version: SCHEMA_VERSION,
            family: "libid".to_owned(),
            name: "test".to_owned(),
            version: version.to_owned(),
            toolchains: serde_json::Value::Null,
            libraries: vec![],
            split: SplitConfig {
                rule: "version".to_owned(),
                unit: String::new(),
                fast_programs_per_library: 1,
                max_heldout_overlap: 0.5,
                refuse_heldout_overlap: 0.95,
                final_split: String::new(),
            },
            binaries,
        }
    }

    #[test]
    fn the_split_holds_out_library_versions_and_the_fast_slice_is_training_data() {
        let corpus = Corpus::from_manifest(PathBuf::from("/"), manifest("v1")).unwrap();
        for binary in &corpus.manifest.binaries {
            let held = corpus.in_split(binary, Split::Heldout);
            assert_eq!(held, binary.library_version == "1.3" || binary.library_version == "1.10", "{}", binary.id);
            assert_ne!(held, corpus.in_split(binary, Split::Train));
        }
        assert_eq!(corpus.fast_programs().len(), 2, "one training program per library");
        for index in corpus.indices(Split::Fast) {
            assert!(corpus.in_split(&corpus.manifest.binaries[index], Split::Train));
        }
        assert_eq!(corpus.indices(Split::Fast).len(), 2);
        let again = Corpus::from_manifest(PathBuf::from("/"), manifest("v1")).unwrap();
        assert_eq!(corpus.identity(), again.identity());
    }

    #[test]
    fn one_version_on_both_sides_is_refused() {
        let mut both = manifest("v1");
        both.binaries[0].split = Role::Heldout;
        let error = Corpus::from_manifest(PathBuf::from("/"), both).unwrap_err();
        assert!(error.message().contains("both the training and the held-out split"), "{error}");
    }

    #[test]
    fn the_final_split_is_its_own_and_holds_out_versions_from_both_other_splits() {
        let mut with_final = manifest("v1");
        let mut extra = with_final.binaries[0].clone();
        extra.id = "zlib-1.4-p0".to_owned();
        extra.library_version = "1.4".to_owned();
        extra.split = Role::Final;
        with_final.binaries.push(extra.clone());
        let corpus = Corpus::from_manifest(PathBuf::from("/"), with_final.clone()).unwrap();
        let index = corpus.manifest.binaries.len() - 1;
        assert_eq!(corpus.indices(Split::Final), [index]);
        for split in [Split::Train, Split::Heldout, Split::Fast, Split::Negative] {
            assert!(!corpus.indices(split).contains(&index), "{}", split.name());
        }
        for (shared, side) in [("1.3", "held-out"), ("1.2", "training")] {
            let mut clash = with_final.clone();
            clash.binaries.last_mut().unwrap().library_version = shared.to_owned();
            let error = Corpus::from_manifest(PathBuf::from("/"), clash).unwrap_err();
            assert!(error.message().contains(&format!("both the {side} and the final split")), "{error}");
        }
    }

    #[test]
    fn the_identity_covers_the_split_and_every_binary_hash() {
        let base = Corpus::from_manifest(PathBuf::from("/"), manifest("v1")).unwrap();
        let mut changed = manifest("v1");
        changed.binaries[3].stripped_sha256 = "other".to_owned();
        assert_ne!(Corpus::from_manifest(PathBuf::from("/"), changed).unwrap().identity(), base.identity());
        let mut split = manifest("v1");
        split.split.fast_programs_per_library = 2;
        assert_ne!(Corpus::from_manifest(PathBuf::from("/"), split).unwrap().identity(), base.identity());
    }

    #[test]
    fn paths_must_stay_inside_the_corpus() {
        let mut escaping = manifest("v1");
        escaping.binaries[0].twin = "../outside".to_owned();
        assert!(Corpus::from_manifest(PathBuf::from("/"), escaping).is_err());
    }
}
