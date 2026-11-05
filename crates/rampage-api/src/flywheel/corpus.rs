//! A built flywheel corpus: its manifest, the deterministic program-level train/held-out split, the fast slice and
//! the slice keys every binary is reported under.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{FlywheelError, hex, sha256_file};

/// The manifest file at the root of a built corpus.
pub const MANIFEST: &str = "manifest.json";
/// The manifest schema this version reads.
pub const SCHEMA_VERSION: u32 = 1;
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
    /// The content address of the corpus: it keys the split, so a new version rotates it.
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
    #[serde(default)]
    pub unit: String,
    /// The share of each library's programs held out, rounded, at least one when a library has two or more.
    pub heldout_fraction: f64,
    /// Training programs per library in the fast slice.
    pub fast_programs_per_library: usize,
}

/// One stripped binary of the corpus with its symbolized twin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusBinary {
    pub id: String,
    /// The program (driver source) the binary was built from: the unit of the split.
    pub program: String,
    /// The library the program drives.
    pub library: String,
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
    /// The slices this binary is reported under, `all` first.
    pub fn slices(&self) -> Vec<String> {
        vec![
            "all".to_owned(),
            format!("arch:{}", self.arch),
            format!("compiler:{}", self.compiler),
            format!("opt:{}", self.opt),
            format!("library:{}", self.library),
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
    /// Every training program.
    Train,
    /// The held-out programs: never shown to a proposer, only measured.
    Heldout,
    /// A fixed small subset of the training programs, to reject bad candidates quickly.
    Fast,
}

impl Split {
    pub fn name(self) -> &'static str {
        match self {
            Split::Train => "train",
            Split::Heldout => "heldout",
            Split::Fast => "fast",
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
            other => Err(format!("unknown split `{other}` (train, heldout or fast)")),
        }
    }
}

/// A loaded corpus with its split.
#[derive(Debug, Clone)]
pub struct Corpus {
    pub root: PathBuf,
    pub manifest: CorpusManifest,
    /// Held-out programs.
    heldout: BTreeSet<String>,
    /// Fast-slice programs (all of them training programs).
    fast: BTreeSet<String>,
}

impl Corpus {
    /// Loads the corpus at `root` and checks every file it lists against its recorded SHA-256, so a binary
    /// changed after the build cannot be measured under the old corpus version.
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

    /// Loads the manifest and computes the split without hashing the files.
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
                "manifest schema {} (this version reads {SCHEMA_VERSION})",
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
        if !(0.0..1.0).contains(&manifest.split.heldout_fraction) {
            return invalid("split.heldout_fraction must be in [0, 1)".to_owned());
        }
        if manifest.binaries.is_empty() || manifest.binaries.len() > MAX_BINARIES {
            return invalid(format!("a corpus lists 1 to {MAX_BINARIES} binaries"));
        }
        let mut ids = BTreeSet::new();
        for binary in &manifest.binaries {
            if !ids.insert(binary.id.as_str()) {
                return invalid(format!("binary id {} is listed twice", binary.id));
            }
            for path in [
                Some(&binary.stripped),
                Some(&binary.twin),
                binary.program_object.as_ref(),
                binary.library_object.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                if Path::new(path).is_absolute() || Path::new(path).components().any(|part| part.as_os_str() == "..") {
                    return invalid(format!("{}: path {path} must stay inside the corpus", binary.id));
                }
            }
            if binary.arch.parse::<rampage_arch::Arch>().is_err() {
                return invalid(format!("{}: unknown architecture {}", binary.id, binary.arch));
            }
        }
        let (heldout, fast) = split_programs(&manifest);
        Ok(Corpus { root, manifest, heldout, fast })
    }

    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// Whether `binary` belongs to `split`.
    pub fn in_split(&self, binary: &CorpusBinary, split: Split) -> bool {
        match split {
            Split::Heldout => self.heldout.contains(&binary.program),
            Split::Train => !self.heldout.contains(&binary.program),
            Split::Fast => self.fast.contains(&binary.program),
        }
    }

    /// The indices of the binaries in `split`, in manifest order.
    pub fn indices(&self, split: Split) -> Vec<usize> {
        let binaries = self.manifest.binaries.iter().enumerate();
        binaries.filter(|(_, binary)| self.in_split(binary, split)).map(|(index, _)| index).collect()
    }

    pub fn heldout_programs(&self) -> &BTreeSet<String> {
        &self.heldout
    }

    pub fn fast_programs(&self) -> &BTreeSet<String> {
        &self.fast
    }

    /// The architectures the corpus holds.
    pub fn arches(&self) -> BTreeSet<String> {
        self.manifest.binaries.iter().map(|binary| binary.arch.clone()).collect()
    }

    /// The SPDX expression covering the corpus libraries, for packs made from them.
    pub fn license(&self) -> String {
        let licenses: BTreeSet<&str> = self
            .manifest
            .libraries
            .iter()
            .filter_map(|library| library.get("license").and_then(serde_json::Value::as_str))
            .collect();
        if licenses.is_empty() {
            "NOASSERTION".to_owned()
        } else {
            licenses.into_iter().collect::<Vec<_>>().join(" AND ")
        }
    }
}

/// The deterministic split: within each library, programs are ordered by SHA-256 of the corpus version and the
/// program name, and the first ones are held out. Keying by the version rotates the split with every corpus
/// version; splitting by program keeps a held-out program's own functions out of training entirely.
pub fn split_programs(manifest: &CorpusManifest) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut by_library: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for binary in &manifest.binaries {
        by_library.entry(binary.library.as_str()).or_default().insert(binary.program.as_str());
    }
    let mut heldout = BTreeSet::new();
    let mut fast = BTreeSet::new();
    for programs in by_library.values() {
        let mut ordered: Vec<(String, &str)> =
            programs.iter().map(|program| (split_key(&manifest.version, program), *program)).collect();
        ordered.sort();
        let count = ordered.len();
        let wanted = (count as f64 * manifest.split.heldout_fraction).round() as usize;
        let held = if count >= 2 { wanted.clamp(1, count - 1) } else { 0 };
        for (position, (_, program)) in ordered.iter().enumerate() {
            if position < held {
                heldout.insert((*program).to_owned());
            } else if position < held + manifest.split.fast_programs_per_library {
                fast.insert((*program).to_owned());
            }
        }
    }
    (heldout, fast)
}

fn split_key(version: &str, program: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rampage flywheel split\0");
    hasher.update(version.as_bytes());
    hasher.update([0]);
    hasher.update(program.as_bytes());
    hex(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str, programs_per_library: usize) -> CorpusManifest {
        let mut binaries = Vec::new();
        for library in ["zlib", "lz4"] {
            for program in 0..programs_per_library {
                for arch in ["x86_64", "aarch64"] {
                    binaries.push(CorpusBinary {
                        id: format!("{library}-p{program}-{arch}"),
                        program: format!("{library}/p{program}"),
                        library: library.to_owned(),
                        arch: arch.to_owned(),
                        compiler: "zig".to_owned(),
                        opt: "O2".to_owned(),
                        stripped: "a".to_owned(),
                        twin: "b".to_owned(),
                        program_object: None,
                        library_object: None,
                        program_names: vec![],
                        stripped_sha256: String::new(),
                        twin_sha256: String::new(),
                        program_object_sha256: None,
                        library_object_sha256: None,
                    });
                }
            }
        }
        CorpusManifest {
            schema_version: 1,
            family: "libid".to_owned(),
            name: "test".to_owned(),
            version: version.to_owned(),
            toolchains: serde_json::Value::Null,
            libraries: vec![],
            split: SplitConfig { unit: String::new(), heldout_fraction: 0.25, fast_programs_per_library: 1 },
            binaries,
        }
    }

    #[test]
    fn the_split_is_by_program_deterministic_and_keyed_by_the_version() {
        let first = Corpus::from_manifest(PathBuf::from("/"), manifest("v1", 4)).unwrap();
        let again = Corpus::from_manifest(PathBuf::from("/"), manifest("v1", 4)).unwrap();
        assert_eq!(first.heldout, again.heldout);
        assert_eq!(first.fast, again.fast);
        // One of four programs per library is held out, and every binary of a program falls on one side.
        assert_eq!(first.heldout.len(), 2);
        for binary in &first.manifest.binaries {
            assert_ne!(first.in_split(binary, Split::Heldout), first.in_split(binary, Split::Train), "{}", binary.id);
            let siblings = first.manifest.binaries.iter().filter(|other| other.program == binary.program);
            for sibling in siblings {
                assert_eq!(first.in_split(binary, Split::Heldout), first.in_split(sibling, Split::Heldout));
            }
        }
        // The fast slice is training data: one program per library.
        assert_eq!(first.fast.len(), 2);
        assert!(first.fast.is_disjoint(&first.heldout));
        for index in first.indices(Split::Fast) {
            assert!(first.in_split(&first.manifest.binaries[index], Split::Train));
        }
        // Another version rotates the split for at least one library across a handful of versions.
        let rotated = (2..10).any(|version| {
            let other = Corpus::from_manifest(PathBuf::from("/"), manifest(&format!("v{version}"), 4)).unwrap();
            other.heldout != first.heldout
        });
        assert!(rotated);
    }

    #[test]
    fn a_library_with_two_programs_holds_one_out_and_one_alone_holds_none() {
        let two = Corpus::from_manifest(PathBuf::from("/"), manifest("v1", 2)).unwrap();
        assert_eq!(two.heldout.len(), 2, "one per library");
        let one = Corpus::from_manifest(PathBuf::from("/"), manifest("v1", 1)).unwrap();
        assert!(one.heldout.is_empty());
    }

    #[test]
    fn paths_must_stay_inside_the_corpus() {
        let mut escaping = manifest("v1", 2);
        escaping.binaries[0].twin = "../outside".to_owned();
        assert!(Corpus::from_manifest(PathBuf::from("/"), escaping).is_err());
    }
}
