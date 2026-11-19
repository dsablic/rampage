use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock, RwLockReadGuard};

use rampage_analysis::discover::{Program, XrefKind};
use rampage_analysis::functions::{self, Names};
use rampage_analysis::strings::{self, FoundString};
use rampage_analysis::triage::{self, Triage};
use rampage_loaders::{Binary, Export, ImageAt, LoadError};
use sha2::{Digest, Sha256};

use crate::annotations::{Annotations, Edit, Field};
use crate::rows::{
    Annotation, AnnotationList, EditResult, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Matcher, Page,
    StringsQuery, Summary,
};
use crate::{ApiError, DecoderInitializationError, Packs};

/// The shortest string listed unless a query asks for shorter ones.
const DEFAULT_STRING_LENGTH: usize = 4;
/// A Raw project with fewer than one discovered function per this many bytes of code gets a `next` hint: firmware
/// averages hundreds of bytes per function, so a handful in a large image means discovery stopped early (startup
/// code, calls through pointers). A small image is held to at least one function.
const RAW_BYTES_PER_FUNCTION: u64 = 16 * 1024;
/// So does one whose discovered function bodies cover less than one part in this many of its code-like bytes: many
/// small functions found from records and literal pools can pass the count while most code stays unreached.
const RAW_COVERAGE_PARTS: u64 = 8;
/// A run of at least this many copies of one byte is fill (erased flash, zeroes, padding), not code.
const RAW_FILL_RUN: usize = 64;

/// Bytes of `bytes` in runs of at least [`RAW_FILL_RUN`] copies of one byte.
fn fill_bytes(bytes: &[u8]) -> u64 {
    let mut fill = 0u64;
    let mut start = 0usize;
    for index in 1..=bytes.len() {
        if index == bytes.len() || bytes[index] != bytes[start] {
            if index - start >= RAW_FILL_RUN {
                fill += (index - start) as u64;
            }
            start = index;
        }
    }
    fill
}

/// What triage measures on a Raw project, and which file-format facts do not apply to it.
pub(crate) fn raw_triage_note(raw: &rampage_loaders::RawCodeImage) -> String {
    let regions = raw.regions().iter().filter(|region| region.backed()).count();
    format!(
        "Raw project ({}): no file header, so build time, libraries, imports, exports, hardening, overlay and \
         imphash do not apply; the hashes and entropy cover the {} mapped region{} with bytes (decoded bytes \
         included) and the sections are the mapped regions, at their mapped addresses",
        raw.profile().language_id(),
        regions,
        if regions == 1 { "" } else { "s" }
    )
}

/// Initialized cache presence only; this is not a history or concurrent-activity attestation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct AnalysisCacheStatus {
    pub program: bool,
    pub strings: bool,
    pub triage: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct PdbImport {
    /// Identity-checked PDB names at virtual addresses, including names not eligible for application.
    pub preview: rampage_loaders::pdb::PdbReport,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub applied: Vec<u64>,
    /// Addresses left unchanged: already named, not discovered entries, or names used elsewhere.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub preserved: Vec<u64>,
}

/// An immutable, process-local checked preview. It borrows its exact project, keeping that project's original
/// binary and image selection in place. It cannot be deserialized or applied to a reloaded project.
pub struct PdbPreview<'project> {
    project: &'project Project,
    image_sha256: [u8; 32],
    pdb: rampage_loaders::pdb::PdbProvenance,
    report: rampage_loaders::pdb::PdbReport,
    approved: Vec<rampage_loaders::pdb::PdbFunction>,
    preserved: Vec<u64>,
}

impl std::fmt::Debug for PdbPreview<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PdbPreview")
            .field("image_sha256", &self.image_sha256)
            .field("pdb", &self.pdb)
            .field("report", &self.report)
            .field("approved", &self.approved)
            .field("preserved", &self.preserved)
            .finish_non_exhaustive()
    }
}

impl PdbPreview<'_> {
    pub fn image_sha256(&self) -> &[u8; 32] {
        &self.image_sha256
    }

    pub fn pdb(&self) -> &rampage_loaders::pdb::PdbProvenance {
        &self.pdb
    }

    pub fn report(&self) -> &rampage_loaders::pdb::PdbReport {
        &self.report
    }

    /// Only these address/name pairs can ever be applied using this preview.
    pub fn approved(&self) -> &[rampage_loaders::pdb::PdbFunction] {
        &self.approved
    }

    pub fn preserved(&self) -> &[u64] {
        &self.preserved
    }
}

pub struct Project {
    pub binary: Binary,
    names: Names,
    pub(crate) annotations: Arc<RwLock<Annotations>>,
    pub(crate) frozen_annotations: Arc<OnceLock<RwLock<Annotations>>>,
    pub(crate) byte_patches: BTreeMap<u64, String>,
    pub(crate) patch_origin: Option<Arc<Project>>,
    pub(crate) patch_source_sha256: OnceLock<[u8; 32]>,
    /// The file a Raw project was opened from, for writing a patched image back in its original container.
    pub(crate) raw_source: OnceLock<std::path::PathBuf>,
    analysis: OnceLock<Result<Analysis, DecoderInitializationError>>,
    analysis_binding: OnceLock<Option<String>>,
    triage: OnceLock<Triage>,
    /// Code regions measured for encryption or packing, computed once with the project's decoder.
    code_regions: OnceLock<Vec<rampage_analysis::code_integrity::CodeRegion>>,
    /// A Cortex-M Raw project's base checked against load-address candidates, computed once.
    base_check: OnceLock<Option<rampage_loaders::raw_base::BaseCheck>>,
    /// A Cortex-M Raw project whose selector left `pointer_tables` unset: why the scan ran automatically.
    pub(crate) pointer_tables_auto: OnceLock<crate::rows::PointerTablesAuto>,
    /// A Cortex-M Raw project reopened with the CRC routines integrity_checks infers as further seeds.
    pub(crate) inferred_seeds: OnceLock<Vec<crate::rows::InferredSeed>>,
    /// Why the reopen with inferred CRC seeds could not be admitted, when it could not.
    pub(crate) inferred_seeds_refused: OnceLock<String>,
    /// Record-pass starts an earlier interpretation of these bytes found, judged again by this project's discovery.
    pub(crate) carried_record_seeds: OnceLock<Vec<u64>>,
    /// A Cortex-M Raw project's starting points, once discovery has run.
    starting_points: OnceLock<Vec<crate::rows::StartingPoint>>,
    /// A Raw project's container streams, found once by integrity_checks.
    pub(crate) container_scan: OnceLock<Arc<crate::integrity::ContainerScan>>,
    /// Strings of at least `DEFAULT_STRING_LENGTH` characters, scanned once.
    strings: OnceLock<Vec<FoundString>>,
    /// The embedded decompiler, built once over the executable segments on first use. Behind a mutex because
    /// Ghidra's decompiler is not thread-safe and a project is shared across threads.
    pub(crate) decompiler: std::sync::Mutex<crate::decompile::DecompilerState>,
    /// Data packs layered over the bundled heuristic databases.
    packs: RwLock<Arc<Packs>>,
    /// Go register-ABI prototypes, derived once on first decompilation.
    pub(crate) go_prototypes: OnceLock<crate::decompile::GoPrototypes>,
    /// Go static string headers, read once from data on first use.
    go_strings: OnceLock<crate::go_strings::GoStrings>,
    /// Objective-C message sends resolved to method implementations, derived once from the analysis.
    objc_dispatch: OnceLock<rampage_analysis::objc_dispatch::Dispatch>,
    /// Where sends can be, so queries that cannot involve one skip resolving them.
    objc_hints: OnceLock<Option<rampage_analysis::objc_dispatch::SendHints>>,
    /// Embedded DWARF name → DIE index, skimmed once on the first DWARF type lookup.
    dwarf_types: OnceLock<Result<Arc<rampage_loaders::debug::DwarfTypeIndex>, String>>,
    go_types: OnceLock<Result<Arc<rampage_loaders::gotypes::GoTypeIndex>, String>>,
    /// The persistent analysis store consulted before discovery, if any.
    analysis_store: RwLock<Option<Arc<crate::AnalysisStore>>>,
    /// What the persistent store did when analysis ran.
    analysis_store_status: OnceLock<crate::AnalysisStoreStatus>,
    /// A fresh analysis still to be written to the store, after the analysis itself is published.
    analysis_store_pending: std::sync::Mutex<Option<PendingStore>>,
    /// Loads and stores at constant addresses, scanned once on the first peripheral query.
    pub(crate) mmio_accesses: OnceLock<Result<Arc<crate::peripherals::AccessIndex>, String>>,
    /// Cortex-M Raw only: flash words code reads or writes through a formed address, scanned once per project for
    /// the decompiler (`decompile::symbols`).
    pub(crate) flash_data_accesses: OnceLock<Vec<(u64, u64)>>,
}

/// A fresh analysis to store: the store, its key, and why an existing entry was rejected, if one was.
struct PendingStore {
    store: Arc<crate::AnalysisStore>,
    key: String,
    rejected: Option<String>,
}

/// Rechecks the frozen view after acquiring the authority read lock. Selecting a lock before a first patch
/// transaction finishes must not let a delayed reader observe that transaction's bytes on an original project.
pub(crate) struct AnnotationReadView<'a> {
    authority: &'a RwLock<Annotations>,
    frozen: &'a OnceLock<RwLock<Annotations>>,
}

impl<'a> AnnotationReadView<'a> {
    pub(crate) fn read(&self) -> std::sync::LockResult<RwLockReadGuard<'a, Annotations>> {
        if let Some(frozen) = self.frozen.get() {
            return frozen.read();
        }
        let current = self.authority.read();
        if let Some(frozen) = self.frozen.get() {
            drop(current);
            return frozen.read();
        }
        current
    }

    pub(crate) fn try_read(&self) -> std::sync::TryLockResult<RwLockReadGuard<'a, Annotations>> {
        if let Some(frozen) = self.frozen.get() {
            return frozen.try_read();
        }
        let current = self.authority.try_read();
        if let Some(frozen) = self.frozen.get() {
            drop(current);
            return frozen.try_read();
        }
        current
    }
}

pub(crate) struct Analysis {
    pub(crate) program: Program,
    /// Indices into `program.xrefs`, ordered by source address.
    pub(crate) xrefs_by_source: Vec<usize>,
    /// Every block, sorted by start, for address-to-function lookups.
    blocks: Vec<BlockSpan>,
}

struct BlockSpan {
    start: u64,
    end: u64,
    function: u64,
    /// The block's position in its function's `blocks`.
    index: usize,
    /// The furthest end of this block and every block that starts before it.
    reach: u64,
}

impl Analysis {
    pub(crate) fn new(program: Program) -> Self {
        let mut blocks: Vec<BlockSpan> = program
            .functions
            .iter()
            .flat_map(|function| {
                function.blocks.iter().enumerate().map(|(index, block)| BlockSpan {
                    start: block.start,
                    end: block.end,
                    function: function.address,
                    index,
                    reach: 0,
                })
            })
            .collect();
        blocks.sort_unstable_by_key(|block| (block.start, block.end, block.function, block.index));
        let mut reach = 0;
        for block in &mut blocks {
            reach = reach.max(block.end);
            block.reach = reach;
        }
        let mut xrefs_by_source: Vec<usize> = (0..program.xrefs.len()).collect();
        xrefs_by_source.sort_unstable_by_key(|&index| (program.xrefs[index].from, program.xrefs[index].to));
        Self { program, xrefs_by_source, blocks }
    }

    pub(crate) fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Every block containing `address`, as `(function, block index)`, latest-starting first. The scan visits
    /// only blocks that start at or before `address` and whose cumulative reach still covers it.
    pub(crate) fn blocks_containing(&self, address: u64) -> impl Iterator<Item = (u64, usize)> + '_ {
        let candidates = self.blocks.partition_point(|block| block.start <= address);
        self.blocks[..candidates]
            .iter()
            .rev()
            .take_while(move |block| block.reach > address)
            .filter(move |block| address < block.end)
            .map(|block| (block.function, block.index))
    }

    /// The start of the function whose block contains `address`, preferring the latest-starting block. Callers
    /// that look up many addresses use this on one checked analysis rather than [`Project::function_containing`],
    /// which rechecks the analysis binding (for a Raw project, a hash of the whole image) on every call.
    pub(crate) fn function_containing(&self, address: u64) -> Option<u64> {
        let candidates = self.blocks.partition_point(|block| block.start <= address);
        self.blocks[..candidates]
            .iter()
            .rev()
            .take_while(|block| block.reach > address)
            .find(|block| address < block.end)
            .map(|block| block.function)
    }
}

impl Project {
    /// Process-local names-only identity for Arc::ptr_eq; not serialized authority or source freshness.
    pub fn names_revision(&self) -> Result<Arc<()>, ApiError> {
        let current = match self.read_annotations_lock().try_read() {
            Ok(current) => current,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(ApiError::Unavailable("annotations are busy".into()));
            }
        };
        Ok(current.names_revision())
    }

    pub(crate) fn inventory_loader_names(&self) -> impl ExactSizeIterator<Item = (u64, &str)> {
        self.names.entries()
    }

    pub(crate) fn inventory_function_name_in<'a>(
        &'a self,
        annotations: &'a Annotations,
        address: u64,
    ) -> Option<&'a str> {
        annotations.name(address).or_else(|| self.names.get(address))
    }

    /// Process-local in-memory annotation identity for `Arc::ptr_eq`; not serialized consent or disk freshness.
    pub fn annotation_revision(&self) -> Result<Arc<()>, ApiError> {
        let current = match self.read_annotations_lock().try_read() {
            Ok(current) => current,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(ApiError::Unavailable("annotations are busy".into()));
            }
        };
        Ok(current.revision())
    }

    /// Refreshed authority nonce, separate from a held snapshot's annotation revision. Every publication or
    /// replay receives a new identity, including changes that restore an earlier value (no value-based ABA).
    pub fn authoritative_annotation_revision(&self) -> Result<Arc<()>, ApiError> {
        let mut annotations =
            self.annotations.try_write().map_err(|_| ApiError::Unavailable("annotations are busy".into()))?;
        annotations.preflight_checked().map_err(ApiError::Invalid)?;
        annotations
            .refresh_validated(|candidate| self.validate_patch_authority(candidate))
            .map_err(ApiError::Invalid)?;
        Ok(annotations.revision())
    }

    /// Observes completed cache initialization without starting, waiting for or reconstructing analysis.
    pub fn analysis_cache_status(&self) -> AnalysisCacheStatus {
        AnalysisCacheStatus {
            program: self.analysis.get().is_some(),
            strings: self.strings.get().is_some(),
            triage: self.triage.get().is_some(),
        }
    }

    /// Tests may observe cache occupancy without conferring authority on its contents.
    #[cfg(test)]
    pub(crate) fn cached_analysis(&self) -> Option<&Analysis> {
        self.analysis.get().and_then(|analysis| analysis.as_ref().ok())
    }

    /// Never initializes discovery or a decoder. A cached failure retains its original typed cause.
    pub(crate) fn cached_analysis_checked(&self) -> Result<Option<&Analysis>, ApiError> {
        let Some(cached) = self.analysis.get() else { return Ok(None) };
        let analysis = cached.as_ref().map_err(DecoderInitializationError::to_api_error)?;
        self.validate_cached_analysis_binding()?;
        Ok(Some(analysis))
    }

    fn validate_cached_analysis_binding(&self) -> Result<(), ApiError> {
        self.binary
            .validate_available_backing_source()
            .map_err(|error| ApiError::Unavailable(format!("cached analysis source: {error}")))?;
        let binding = crate::decoder::analysis_binding(&self.binary).map_err(|error| error.to_api_error())?;
        if binding.is_some() && self.analysis_binding.get() != Some(&binding) {
            return Err(ApiError::Unavailable("cached analysis belongs to another Raw decoder interpretation".into()));
        }
        Ok(())
    }
    /// A project whose annotations live in memory only.
    pub fn new(binary: Binary) -> Self {
        Self::with_annotations(binary, Annotations::in_memory())
    }

    /// The binary at `path` as a peer to compare this one with: the slice of this binary's architecture, with its
    /// annotations in memory only. A file that loads, but not in this architecture, is reported as a mismatch.
    pub fn open_peer(&self, path: &Path) -> Result<Project, ApiError> {
        self.open_peer_image(path, None)
    }

    /// [`Project::open_peer`] for the executable embedded in `path` at `image`, or the whole file without one.
    pub fn open_peer_image(&self, path: &Path, image: Option<ImageAt>) -> Result<Project, ApiError> {
        let arch = self.binary.arch;
        match Binary::open_image(path, image, Some(arch)) {
            Ok(binary) => Ok(Project::new(binary)),
            Err(source @ LoadError::Unsupported(_)) if Binary::open_image(path, image, None).is_ok() => Err(
                ApiError::Invalid(format!("{}: {source}; a comparison needs both binaries in {arch}", path.display())),
            ),
            Err(source) => Err(ApiError::Load { path: path.to_owned(), source }),
        }
    }

    /// Raw projects retain supplied annotation values in memory only, detached from any persistent log.
    pub fn with_annotations(binary: Binary, mut annotations: Annotations) -> Self {
        if binary.format == rampage_loaders::Format::Raw {
            annotations = annotations.snapshot();
        }
        let names = Names::new(&binary);
        let frozen_annotations = Arc::new(OnceLock::new());
        if !annotations.patches().is_empty() {
            let _ = frozen_annotations.set(RwLock::new(annotations.original_read_snapshot()));
        }
        let frozen = Arc::clone(&frozen_annotations);
        annotations.set_patch_freezer(Arc::new(move |view| {
            let _ = frozen.set(RwLock::new(view.read_snapshot()));
        }));
        Self {
            binary,
            names,
            annotations: Arc::new(RwLock::new(annotations)),
            frozen_annotations,
            byte_patches: BTreeMap::new(),
            patch_origin: None,
            patch_source_sha256: OnceLock::new(),
            raw_source: OnceLock::new(),
            analysis: OnceLock::new(),
            analysis_binding: OnceLock::new(),
            triage: OnceLock::new(),
            code_regions: OnceLock::new(),
            base_check: OnceLock::new(),
            pointer_tables_auto: OnceLock::new(),
            inferred_seeds: OnceLock::new(),
            inferred_seeds_refused: OnceLock::new(),
            carried_record_seeds: OnceLock::new(),
            starting_points: OnceLock::new(),
            container_scan: OnceLock::new(),
            strings: OnceLock::new(),
            decompiler: std::sync::Mutex::new(crate::decompile::DecompilerState::default()),
            packs: RwLock::default(),
            go_prototypes: OnceLock::new(),
            go_strings: OnceLock::new(),
            objc_dispatch: OnceLock::new(),
            objc_hints: OnceLock::new(),
            dwarf_types: OnceLock::new(),
            go_types: OnceLock::new(),
            analysis_store: RwLock::new(crate::AnalysisStore::from_env()),
            analysis_store_status: OnceLock::new(),
            analysis_store_pending: std::sync::Mutex::new(None),
            mmio_accesses: OnceLock::new(),
            flash_data_accesses: OnceLock::new(),
        }
    }

    /// Selects the persistent analysis store (`None` disables it) for analyses that have not run yet. Projects
    /// start with [`crate::AnalysisStore::from_env`]. The store's key covers the bytes `binary` was loaded from, so
    /// a project built from a `Binary` whose metadata was edited after loading must disable it.
    pub fn set_analysis_store(&self, store: Option<Arc<crate::AnalysisStore>>) {
        *self.analysis_store.write().unwrap_or_else(|poison| poison.into_inner()) = store;
    }

    /// The persistent store's part in this project's analysis, without starting it.
    pub fn analysis_store_status(&self) -> crate::AnalysisStoreStatus {
        if let Some(status) = self.analysis_store_status.get() {
            return status.clone();
        }
        let state = if self.analysis_store.read().unwrap_or_else(|poison| poison.into_inner()).is_none() {
            "disabled"
        } else if self.patch_origin.is_some() || self.binary.format == rampage_loaders::Format::Snapshot {
            "unsupported"
        } else {
            "pending"
        };
        crate::AnalysisStoreStatus::new(state, None, None)
    }

    /// Discovery through the persistent store: a verified entry for this exact input, else a fresh analysis that
    /// is then stored. Byte-patched views are never stored; their bytes are not the file's.
    fn discover_through_store(&self, binding: Option<&str>) -> Result<Program, DecoderInitializationError> {
        use crate::AnalysisStoreStatus as Status;
        use crate::analysis_cache::Lookup;
        let carried = self.carried_record_seeds.get().map_or(&[][..], Vec::as_slice);
        let fresh = || {
            functions::analyze_with_carried_seeds(
                &self.binary,
                || crate::decoder::decoder_for_project(&self.binary),
                carried,
            )
        };
        let store = self.analysis_store.read().unwrap_or_else(|poison| poison.into_inner()).clone();
        let Some(store) = store else {
            let _ = self.analysis_store_status.set(Status::new("disabled", None, None));
            return fresh();
        };
        let key = if self.patch_origin.is_some() || !carried.is_empty() {
            None
        } else {
            crate::analysis_cache::key(&self.binary, binding)
        };
        let Some(key) = key else {
            let _ = self.analysis_store_status.set(Status::new("unsupported", None, None));
            return fresh();
        };
        let rejected = match store.load(&key) {
            Lookup::Hit(program) => {
                let _ = self.analysis_store_status.set(Status::new("hit", Some(key), None));
                return Ok(*program);
            }
            Lookup::Absent => None,
            Lookup::Rejected(reason) => Some(reason),
        };
        let program = fresh()?;
        *self.analysis_store_pending.lock().unwrap_or_else(|poison| poison.into_inner()) =
            Some(PendingStore { store, key, rejected });
        Ok(program)
    }

    /// Writes a fresh analysis to the store once it is published, so concurrent callers never wait on the write;
    /// the write itself waits only briefly for another writer and is skipped when the store stays busy.
    fn finish_store(&self, analysis: &Analysis) {
        let pending = self.analysis_store_pending.lock().unwrap_or_else(|poison| poison.into_inner()).take();
        let Some(PendingStore { store, key, rejected }) = pending else { return };
        let stored = store.store(&key, &analysis.program);
        let (state, detail) = match (rejected, stored) {
            (Some(reason), Ok(())) => ("rejected", format!("{reason}; analysed fresh and stored")),
            (Some(reason), Err(error)) => ("rejected", format!("{reason}; analysed fresh, {error}")),
            (None, Ok(())) => ("miss", "analysed fresh and stored".to_owned()),
            (None, Err(error)) => ("miss", format!("analysed fresh, {error}")),
        };
        let _ = self.analysis_store_status.set(crate::AnalysisStoreStatus::new(state, Some(key), Some(detail)));
    }

    /// Layers `packs` over the bundled databases for identification, tool detection, YARA and capa.
    pub fn set_packs(&self, packs: Arc<Packs>) {
        *self.packs.write().expect("packs lock") = packs;
    }

    /// The data packs in effect.
    pub fn packs(&self) -> Arc<Packs> {
        Arc::clone(&self.packs.read().expect("packs lock"))
    }

    pub(crate) fn annotations(&self) -> RwLockReadGuard<'_, Annotations> {
        self.read_annotations_lock().read().expect("annotations lock")
    }

    pub(crate) fn read_annotations_lock(&self) -> AnnotationReadView<'_> {
        AnnotationReadView { authority: &self.annotations, frozen: &self.frozen_annotations }
    }

    /// Refreshes the authoritative annotation writer. Held effective snapshots keep their frozen read view;
    /// acquire `effective_snapshot` to observe a newer byte or annotation revision.
    pub fn refresh_annotations(&self) -> Result<bool, ApiError> {
        self.annotations
            .write()
            .expect("annotations lock")
            .refresh_validated(|candidate| self.validate_patch_authority(candidate))
            .map_err(ApiError::Invalid)
    }

    /// The name at `address`: the user's, or else a symbol, export, stub or import-slot name.
    pub fn name_at(&self, address: u64) -> Option<String> {
        let annotations = self.annotations();
        if let Some(name) = annotations.name(address).or_else(|| self.names.get(address)) {
            return Some(name.to_owned());
        }
        let peripherals = annotations.peripheral_map();
        drop(annotations);
        if peripherals.is_empty() { None } else { peripherals.name(address) }
    }

    /// The user's or a symbol's name at `address`, never a peripheral register's.
    pub(crate) fn symbolic_name_at(&self, address: u64) -> Option<String> {
        let annotations = self.annotations();
        annotations.name(address).or_else(|| self.names.get(address)).map(str::to_owned)
    }

    /// The function's name: the user's, a symbol's, or `sub_<hex>`.
    pub fn function_name(&self, address: u64) -> String {
        self.function_name_in(&self.annotations(), address)
    }

    pub(crate) fn function_name_in(&self, annotations: &Annotations, address: u64) -> String {
        annotations.name(address).map_or_else(|| self.names.function_name(address), str::to_owned)
    }

    /// The user's comment at `address`.
    pub fn comment_at(&self, address: u64) -> Option<String> {
        self.annotations().comment(address).map(str::to_owned)
    }

    /// The address a name refers to: a user name, a symbol, export or stub name, or an import name, which finds
    /// its ELF `<import>@plt` stub, or else its import slot.
    pub(crate) fn address_named(&self, annotations: &Annotations, name: &str) -> Option<u64> {
        annotations.address_of(name).or_else(|| self.symbol_address(name))
    }

    /// The address a name refers to apart from the user's names.
    /// The symbol, export, stub or import-slot name at `address`, ignoring the user's names.
    pub(crate) fn symbol_name(&self, address: u64) -> Option<&str> {
        self.names.get(address)
    }

    pub(crate) fn symbol_address(&self, name: &str) -> Option<u64> {
        self.names
            .address_of(name)
            .or_else(|| self.names.address_of(&format!("{name}@plt")))
            .or_else(|| self.names.address_of(&format!("__imp_{name}")))
    }

    /// Names `address` (`None` removes the user's name). Names must be identifiers not used elsewhere, so they
    /// keep resolving to one address.
    pub fn rename(&self, address: u64, name: Option<&str>) -> Result<EditResult, ApiError> {
        if let Some(name) = name {
            check_name(name).map_err(ApiError::Invalid)?;
        }
        // Check and set under the same locks, this process's and the log's, so that no two clients, in this
        // process or another, can give one name to two addresses.
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let value = name.map(str::to_owned);
        let changed = self.annotations.write().expect("annotations lock").locked(|annotations| {
            if let Some(name) = name
                && let Some(existing) = self.address_named(annotations, name)
                && existing != address
            {
                return Err(ApiError::Invalid(format!("{name:?} already names {existing:#x}")));
            }
            annotations
                .set_validated(Field::Name, address, value.clone(), |candidate| {
                    if candidate.globals().is_empty() && candidate.data_types().is_empty() {
                        return Ok(());
                    }
                    self.validate_annotation_snapshot(&state, &options, candidate)
                })
                .map_err(ApiError::Invalid)
        })?;
        Ok(EditResult { address, field: Field::Name, value, changed })
    }

    pub(crate) fn rename_if_default(&self, address: u64, name: &str) -> Result<bool, ApiError> {
        check_name(name).map_err(ApiError::Invalid)?;
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        self.annotations.write().expect("annotations lock").locked_staged_checked(|current| {
            self.validate_patch_context(current)?;
            if !crate::workflows::is_default_name(&self.function_name_in(current, address), address)
                || self.address_named(current, name).is_some_and(|other| other != address)
            {
                return Ok(false);
            }
            current
                .set_validated(Field::Name, address, Some(name.to_owned()), |candidate| {
                    self.validate_annotation_snapshot(&state, &options, candidate)
                })
                .map_err(ApiError::Invalid)
        })
    }

    /// Previews names from an explicit matching PDB, or applies them as one undoable annotation batch.
    /// Only unnamed, already discovered code-function entries are named; symbols, exports and user names win.
    /// This does not import PDB types, layouts, signatures or undiscovered function starts.
    pub fn import_pdb_names(&self, path: &Path, apply: bool) -> Result<PdbImport, ApiError> {
        let preview = rampage_loaders::pdb::matched_symbols(&self.binary, path)
            .map_err(|error| ApiError::Invalid(error.to_string()))?;
        // The reader proposes only unique names that pass `check_name`; anything else it omits with a warning.
        debug_assert!(preview.functions.iter().all(|function| check_name(&function.name).is_ok()));
        let entries: std::collections::BTreeSet<_> =
            self.analysis()?.program.functions.iter().map(|function| function.address).collect();
        let candidates = |annotations: &Annotations| {
            let mut changes = Vec::new();
            let mut preserved = Vec::new();
            for function in &preview.functions {
                let address = function.address;
                if !entries.contains(&address)
                    || annotations.name(address).is_some()
                    || self.names.get(address).is_some()
                    || self.address_named(annotations, &function.name).is_some_and(|existing| existing != address)
                {
                    preserved.push(address);
                } else {
                    changes.push((Field::Name, address, Some(function.name.clone())));
                }
            }
            (changes, preserved)
        };
        if !apply {
            let (_, preserved) = candidates(&self.annotations());
            return Ok(PdbImport { preview, applied: Vec::new(), preserved });
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let (applied, preserved) = self.annotations.write().expect("annotations lock").locked(|annotations| {
            let (changes, preserved) = candidates(annotations);
            let changed = annotations
                .set_batch_validated(&changes, |candidate| {
                    if candidate.globals().is_empty() && candidate.data_types().is_empty() {
                        return Ok(());
                    }
                    self.validate_annotation_snapshot(&state, &options, candidate)
                })
                .map_err(ApiError::Invalid)?;
            let applied = changes
                .into_iter()
                .zip(changed)
                .filter_map(|((_, address, _), changed)| changed.then_some(address))
                .collect();
            Ok((applied, preserved))
        })?;
        Ok(PdbImport { preview, applied, preserved })
    }

    /// Checks an explicit matching PDB without editing annotations or undo history. The receipt binds the checked
    /// report and approved pairs to this project, its selected image digest and the PDB's bytes and provenance.
    /// Observable source changes are refused; neither source checks nor GUID/age matching authenticate a PDB or
    /// provide an atomic filesystem snapshot or race-free mapped reads.
    pub fn preview_pdb_names(&self, path: &Path) -> Result<PdbPreview<'_>, ApiError> {
        let image_sha256 = self.pdb_image_digest()?;
        let (report, pdb) = rampage_loaders::pdb::matched_symbols_checked(&self.binary, path)
            .map_err(|error| ApiError::Invalid(error.to_string()))?;
        // The reader proposes only unique names that pass `check_name`; anything else it omits with a warning.
        debug_assert!(report.functions.iter().all(|function| check_name(&function.name).is_ok()));
        self.check_pdb_backing()?;
        let analysis = self.analysis();
        self.check_pdb_backing()?;
        let entries: std::collections::BTreeSet<_> =
            analysis?.program.functions.iter().map(|function| function.address).collect();
        let annotations = self.annotations();
        let mut approved = Vec::new();
        let mut preserved = Vec::new();
        for function in &report.functions {
            if entries.contains(&function.address) && self.pdb_name_eligible(&annotations, function) {
                approved.push(function.clone());
            } else {
                preserved.push(function.address);
            }
        }
        if self.pdb_image_digest()? != image_sha256 {
            return Err(ApiError::Invalid("selected image changed during PDB preview".to_owned()));
        }
        Ok(PdbPreview { project: self, image_sha256, pdb, report, approved, preserved })
    }

    /// Applies only the preview's cached approved pairs that remain eligible under the annotation transaction
    /// lock. Later labels and conflicts can shrink this set; clearing preview-preserved names cannot enlarge it.
    /// Stale validation publishes no refreshed annotation cache or history. External edits remain for a later refresh.
    /// The whole batch is one same-process undo step, not durable cross-process undo.
    pub fn apply_pdb_names(&self, preview: &PdbPreview<'_>) -> Result<PdbImport, ApiError> {
        if !std::ptr::eq(self, preview.project) {
            return Err(ApiError::Invalid("PDB preview belongs to a different project; preview again".to_owned()));
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        self.validate_pdb_preview(preview)?;
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        self.commit_pdb_preview(preview, &state, &options)
    }

    fn commit_pdb_preview(
        &self,
        preview: &PdbPreview<'_>,
        state: &crate::decompile::DecompilerState,
        options: &rampage_decompiler::DecompilerOptions,
    ) -> Result<PdbImport, ApiError> {
        let (applied, preserved) =
            self.annotations.write().expect("annotations lock").locked_staged(|annotations| {
                self.validate_pdb_preview(preview)?;
                let mut preserved = preview.preserved.clone();
                let mut changes = Vec::new();
                for function in &preview.approved {
                    if self.pdb_name_eligible(annotations, function) {
                        changes.push((Field::Name, function.address, Some(function.name.clone())));
                    } else {
                        preserved.push(function.address);
                    }
                }
                preserved.sort_unstable();
                let changed = annotations
                    .set_batch_validated(&changes, |candidate| {
                        self.binary.validate_backing_source().map_err(|error| error.to_string())?;
                        let result = if candidate.globals().is_empty() && candidate.data_types().is_empty() {
                            Ok(())
                        } else {
                            self.validate_annotation_snapshot(state, options, candidate)
                        };
                        self.binary.validate_backing_source().map_err(|error| error.to_string())?;
                        result?;
                        self.validate_pdb_preview(preview).map_err(|error| error.to_string())
                    })
                    .map_err(ApiError::Invalid)?;
                let applied = changes
                    .into_iter()
                    .zip(changed)
                    .filter_map(|((_, address, _), changed)| changed.then_some(address))
                    .collect();
                Ok((applied, preserved))
            })?;
        Ok(PdbImport { preview: preview.report.clone(), applied, preserved })
    }

    fn pdb_name_eligible(&self, annotations: &Annotations, function: &rampage_loaders::pdb::PdbFunction) -> bool {
        annotations.name(function.address).is_none()
            && self.names.get(function.address).is_none()
            && !self.address_named(annotations, &function.name).is_some_and(|existing| existing != function.address)
    }

    fn check_pdb_backing(&self) -> Result<(), ApiError> {
        self.binary.validate_backing_source().map_err(|error| ApiError::Invalid(error.to_string()))
    }

    fn pdb_image_digest(&self) -> Result<[u8; 32], ApiError> {
        self.check_pdb_backing()?;
        let digest = Sha256::digest(self.binary.image_bytes()).into();
        self.check_pdb_backing()?;
        Ok(digest)
    }

    fn validate_pdb_preview(&self, preview: &PdbPreview<'_>) -> Result<(), ApiError> {
        self.check_pdb_backing()?;
        preview.pdb.validate_current().map_err(|error| ApiError::Invalid(error.to_string()))?;
        if self.pdb_image_digest()? != preview.image_sha256 {
            return Err(ApiError::Invalid("selected image changed since PDB preview; preview again".to_owned()));
        }
        Ok(())
    }

    /// Comments the instruction or data at `address` (`None` or blank text removes the comment).
    pub fn comment(&self, address: u64, text: Option<&str>) -> Result<EditResult, ApiError> {
        let value = text.map(str::trim).filter(|text| !text.is_empty()).map(str::to_owned);
        let changed = self
            .annotations
            .write()
            .expect("annotations lock")
            .set(Field::Comment, address, value.clone())
            .map_err(ApiError::Invalid)?;
        Ok(EditResult { address, field: Field::Comment, value, changed })
    }

    /// Reverts the last edit, or batch of edits, made through this project in this process. Returns its edits;
    /// empty when there was nothing to undo.
    pub fn undo(&self) -> Result<Vec<Edit>, ApiError> {
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        self.annotations.write().expect("annotations lock").locked_staged_history(false, |annotations| {
            self.validate_patch_context(annotations)?;
            let previous = crate::type_library::stored_declarations(annotations)?;
            annotations
                .undo_validated(|candidate| self.validate_history_snapshot(&state, &options, &previous, candidate))
                .map_err(ApiError::Invalid)
        })
    }

    /// Drops the last edit or batch from this project's undo history without reverting it: the way past a step
    /// another client's edits block from undoing, which otherwise blocks every earlier step. Its edits stay in
    /// effect and the log is not rewritten. Refuses, unless `force`, a step no other client's edit blocks, since
    /// undo can still revert it and clients sharing this project share its history. Returns its edits; empty when
    /// there was nothing to undo.
    pub fn discard_undo_step(&self, force: bool) -> Result<Vec<Edit>, ApiError> {
        self.annotations.write().expect("annotations lock").discard_undo_step(force).map_err(ApiError::Invalid)
    }

    /// Reapplies the last undone edit or batch. Returns its edits; empty when there was nothing to redo.
    pub fn redo(&self) -> Result<Vec<Edit>, ApiError> {
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        self.annotations.write().expect("annotations lock").locked_staged_history(true, |annotations| {
            self.validate_patch_context(annotations)?;
            let previous = crate::type_library::stored_declarations(annotations)?;
            annotations
                .redo_validated(|candidate| self.validate_history_snapshot(&state, &options, &previous, candidate))
                .map_err(ApiError::Invalid)
        })
    }

    fn validate_history_snapshot(
        &self,
        state: &crate::decompile::DecompilerState,
        options: &rampage_decompiler::DecompilerOptions,
        previous: &[crate::annotations::LibraryDeclaration],
        candidate: &Annotations,
    ) -> Result<(), String> {
        candidate.validate_patches()?;
        if &self.byte_patches != candidate.patches() {
            let project = self.patch_validation_project(candidate)?;
            let mut fresh = crate::decompile::DecompilerState::default();
            fresh.options = Some(options.clone());
            fresh.worker = state.worker.clone();
            return project.validate_history_snapshot(&fresh, options, previous, candidate);
        }
        self.validate_type_library_transition(state, options, previous, candidate)
            .map_err(|error| error.to_string())?;
        self.validate_annotation_snapshot(state, options, candidate)
    }

    /// Every user name and comment, by address.
    pub fn annotation_list(&self) -> AnnotationList {
        let annotations = self.annotations();
        let rows = |map: &BTreeMap<u64, String>| {
            map.iter().map(|(&address, text)| Annotation { address, text: text.clone() }).collect()
        };
        AnnotationList {
            warnings: annotations.warnings(),
            names: rows(annotations.names()),
            comments: rows(annotations.comments()),
            signatures: rows(annotations.signatures()),
            types: rows(annotations.types()),
            globals: rows(annotations.globals()),
            local_names: rows(annotations.local_names()),
            local_types: rows(annotations.local_types()),
            type_hints: rows(annotations.type_hints()),
            type_library: rows(annotations.type_library()),
            debug_types: rows(annotations.debug_types()),
            data_types: rows(annotations.data_types()),
            operand_types: rows(annotations.operand_types()),
        }
    }

    pub fn summary(&self) -> Summary<'_> {
        // Only from an analysis that already ran: binary_info never starts discovery itself.
        let base_check = self.base_check();
        let wrong_base = base_check.and_then(|check| check.next.clone());
        let next = match (wrong_base, self.raw_discovery_hint().or_else(|| self.starting_points_hint())) {
            (Some(base), Some(discovery)) => Some(format!("{base} {discovery}")),
            (base, discovery) => base.or(discovery),
        };
        let binary = &self.binary;
        Summary {
            format: binary.format,
            arch: binary.arch,
            slices: &binary.slices,
            embedded: binary.embedded,
            entry: binary.entry,
            segments: &binary.segments,
            sections: &binary.sections,
            symbols: binary.symbols.len(),
            imports: binary.imports.len(),
            exports: binary.exports.len(),
            function_starts: binary.function_starts.len(),
            warnings: &binary.warnings,
            provenance: binary.provenance.as_deref(),
            snapshot_modules: &binary.snapshot_modules,
            snapshot_registers: &binary.snapshot_registers,
            snapshot_target: binary.snapshot_target.as_ref(),
            raw: binary.raw_code_image().map(|raw| crate::rows::RawSummary {
                profile: raw.profile(),
                base_address: raw.base(),
                length: raw.length(),
                seed_count: raw.seeds().len(),
                regions: raw.regions(),
                records: raw.records(),
                esp: raw.esp(),
                vector_table: raw.vector_table(),
                pointer_tables: match (raw.pointer_tables(), self.pointer_tables_auto.get()) {
                    (None, None) => None,
                    (tables, automatic) => Some(crate::rows::RawPointerTables { tables, automatic }),
                },
                scatter_load: raw.scatter_load(),
                base_check,
                inferred_seeds: self.inferred_seeds.get().map_or(&[], Vec::as_slice),
                starting_points: self.starting_points(),
                inferred_seeds_refused: self.inferred_seeds_refused.get().map(String::as_str),
                record_seeds: self
                    .analysis
                    .get()
                    .and_then(|analysis| analysis.as_ref().ok())
                    .map(|analysis| &analysis.program.record_seeds)
                    .filter(|record| !record.is_empty())
                    .map(|record| crate::rows::RecordSeedsRow {
                        seeds: record.seeds.len(),
                        rounds: record.rounds,
                        work: record.work,
                        truncated: record.truncated,
                    }),
            }),
            analysis_store: self.analysis_store_status(),
            encrypted_or_packed_code: self.encrypted_regions().cloned().collect(),
            next,
        }
    }

    /// A Cortex-M Raw project's first functions worth reading, once discovery has run (binary_info never starts it).
    fn starting_points(&self) -> &[crate::rows::StartingPoint] {
        if !self.binary.m_profile() || !self.analysis.get().is_some_and(Result::is_ok) {
            return &[];
        }
        self.starting_points.get_or_init(|| self.compute_starting_points())
    }

    /// For a Cortex-M Raw project whose discovery has not run (an explicit `pointer_tables` keeps it lazy), how to
    /// get the starting points binary_info would name.
    fn starting_points_hint(&self) -> Option<String> {
        (self.binary.raw_code_image().is_some() && self.binary.m_profile() && self.analysis.get().is_none()).then(
            || {
                "Discovery has not run for this project yet (an explicit pointer_tables keeps it lazy): call \
             list_functions, then binary_info again to see raw.starting_points, the functions to read first."
                    .to_owned()
            },
        )
    }

    fn compute_starting_points(&self) -> Vec<crate::rows::StartingPoint> {
        let mut points = self.cortex_m_starting_points().unwrap_or_default();
        for seed in self.inferred_seeds.get().into_iter().flatten() {
            let reason = match seed.kind {
                crate::rows::InferredSeedKind::CrcCaller => {
                    "calls an inferred CRC routine directly; nothing discovered calls it (raw.inferred_seeds)"
                }
                crate::rows::InferredSeedKind::CrcRoutine => {
                    "a CRC routine integrity_checks infers from its polynomial literal (raw.inferred_seeds)"
                }
            };
            crate::workflows::add_starting_point(self, &mut points, seed.address, reason.to_owned());
        }
        points
    }

    /// For a Cortex-M Raw project mapped from a byte range (not records, which state their addresses), its base
    /// checked against load-address candidates for the primary region's bytes, once per project.
    pub fn base_check(&self) -> Option<&rampage_loaders::raw_base::BaseCheck> {
        self.base_check
            .get_or_init(|| {
                let raw = self.binary.raw_code_image()?;
                if !raw.profile().m_profile() || raw.records().is_some() {
                    return None;
                }
                let primary = raw.regions().first().filter(|region| region.backed())?;
                let bytes = self.binary.image_bytes().get(primary.data_range())?;
                let entry_offset = raw
                    .entry()
                    .filter(|entry| primary.range().contains(entry))
                    .map(|entry| entry - primary.base_address);
                let regions: Vec<std::ops::Range<u64>> = raw.regions().iter().map(|region| region.range()).collect();
                Some(rampage_loaders::raw_base::check_base(
                    bytes,
                    primary.base_address,
                    entry_offset,
                    &regions,
                    raw.scatter_load(),
                ))
            })
            .as_ref()
    }

    /// The code regions judged encrypted or packed.
    pub fn encrypted_regions(&self) -> impl Iterator<Item = &rampage_analysis::code_integrity::CodeRegion> {
        self.code_regions().iter().filter(|region| region.verdict.is_some())
    }

    /// [`Self::functions`], with the code regions discovery left unexplored and the metadata entry points in each.
    pub fn functions_page(&self, query: &FunctionsQuery) -> Result<crate::rows::FunctionsPage, ApiError> {
        let page = self.functions(query)?;
        let starts: Vec<u64> = functions::from_symbols(&self.binary)
            .iter()
            .map(|function| function.address)
            .chain(self.binary.function_starts.iter().copied())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let unexplored_code = self
            .encrypted_regions()
            .map(|region| crate::rows::UnexploredCode {
                region: region.clone(),
                known_entry_points: starts.iter().filter(|&&start| region.contains(start)).count(),
                note: format!(
                    "not explored for functions: {}. Its symbols, exports and function starts are real entry points \
                     whose bytes only become code at run time; decompiling there is refused",
                    region.explain()
                ),
            })
            .collect();
        Ok(crate::rows::FunctionsPage {
            page,
            unexplored_code,
            next: self.raw_discovery_hint(),
            note: self.pointer_tables_note(),
        })
    }

    /// For a Cortex-M Raw project whose pointer-table scan ran automatically, what ran and why.
    pub fn pointer_tables_note(&self) -> Option<String> {
        let auto = self.pointer_tables_auto.get()?;
        let before = format!(
            "Discovery from the entry, seeds, vector table, scatter-load jump and data records found {} function{} \
             covering {} of {} KiB of code (fewer than one per 16 KiB, or under an eighth of the code)",
            auto.functions_before,
            if auto.functions_before == 1 { "" } else { "s" },
            auto.covered_bytes.div_ceil(1024),
            auto.code_bytes.div_ceil(1024)
        );
        Some(match (self.binary.raw_code_image().and_then(|raw| raw.pointer_tables()), &auto.refused) {
            _ if auto.outcome == "found_none" => format!(
                "{before}, so the pointer-table scan ran automatically and accepted no table; the project is that of \
                 \"pointer_tables\": false"
            ),
            (Some(tables), _) if auto.applied => format!(
                "{before}, so the pointer-table scan ran automatically: {} accepted table{} seeded {} function \
                 start{}; binary_info raw.pointer_tables lists each table with its evidence. Pass \
                 \"pointer_tables\": false to turn the scan off",
                tables.accepted_tables,
                if tables.accepted_tables == 1 { "" } else { "s" },
                tables.seeds,
                if tables.seeds == 1 { "" } else { "s" },
            ),
            (_, refused) => format!(
                "{before}; the automatic pointer-table scan was not applied: {}",
                refused.as_deref().unwrap_or("no tables")
            ),
        })
    }

    /// For a Raw project whose discovery already ran: the functions found, the bytes of backed code and the bytes
    /// their bodies cover, when that is fewer than one function per 16 KiB of code (none at all in a smaller image)
    /// or the bodies cover less than an eighth of the code.
    pub(crate) fn raw_discovery_sparse(&self) -> Option<crate::rows::RawCoverage> {
        let raw = self.binary.raw_code_image()?;
        let code: u64 = raw
            .regions()
            .iter()
            .filter(|region| region.kind == rampage_loaders::RawRegionKind::Code && region.backed())
            .map(|region| region.length)
            .sum();
        let program = &self.analysis.get()?.as_ref().ok()?.program;
        let found = program.functions.len();
        let mut blocks: Vec<(u64, u64)> = program
            .functions
            .iter()
            .flat_map(|function| function.blocks.iter().map(|block| (block.start, block.end)))
            .collect();
        blocks.sort_unstable();
        let (mut covered, mut reached) = (0u64, 0u64);
        for (start, end) in blocks {
            let start = start.max(reached);
            if end > start {
                covered += end - start;
                reached = end;
            }
        }
        let few = found as u64 * RAW_BYTES_PER_FUNCTION < code.max(RAW_BYTES_PER_FUNCTION);
        // Coverage is judged against code-like bytes: runs of one repeated byte (erased flash, zero fill, padding)
        // are no code to reach.
        let fill: u64 = raw
            .regions()
            .iter()
            .filter(|region| region.kind == rampage_loaders::RawRegionKind::Code && region.backed())
            .map(|region| fill_bytes(&self.binary.image_bytes()[region.data_range()]))
            .sum();
        let thin = covered * RAW_COVERAGE_PARTS < code.saturating_sub(fill);
        (few || thin).then_some(crate::rows::RawCoverage { functions: found, code_bytes: code, covered_bytes: covered })
    }

    /// For a Raw project whose discovery, already run, is sparse (see [`Project::raw_discovery_sparse`]), the
    /// selector options that would find more: pointer-table seeding on Cortex-M, and mapping the startup copies when
    /// `scatter_load` false left them unmapped. None otherwise, when no option
    /// applies, or before discovery has run.
    pub fn raw_discovery_hint(&self) -> Option<String> {
        let raw = self.binary.raw_code_image()?;
        let crate::rows::RawCoverage { functions: found, code_bytes: code, covered_bytes: covered } =
            self.raw_discovery_sparse()?;
        let mut steps = Vec::new();
        let automatic = self.pointer_tables_auto.get();
        if let Some(auto) = automatic.filter(|auto| auto.outcome == "refused") {
            steps.push(format!(
                "the automatic pointer-table scan was refused ({}): map less (offset/length) or give seeds",
                auto.refused.as_deref().unwrap_or("no reason given")
            ));
        }
        if raw.profile().m_profile() && raw.pointer_tables().is_none() && automatic.is_none() {
            steps.push(
                "add \"pointer_tables\": true to raw to seed functions from tables of code pointers (handler arrays, \
                 command tables); binary_info then reports each table with its evidence"
                    .to_owned(),
            );
        }
        let unmapped = raw.scatter_load().map_or(0, |scatter| {
            scatter
                .copies
                .iter()
                .filter(|copy| {
                    copy.not_mapped_reason == Some(rampage_loaders::raw_scatter::NotMappedReason::NotRequested)
                        && copy.kind != rampage_loaders::raw_scatter::CopyKind::Computed
                })
                .count()
        });
        if unmapped > 0 {
            steps.push(format!(
                "drop \"scatter_load\": false to map the {unmapped} startup copies raw.scatter_load lists at their run \
                 addresses, so discovery continues into the copied code"
            ));
        }
        (!steps.is_empty()).then(|| {
            format!(
                "Discovery from the entry and seeds found {found} function{} covering {} of {} KiB of code: {}.",
                if found == 1 { "" } else { "s" },
                covered.div_ceil(1024),
                code.div_ceil(1024),
                steps.join("; ")
            )
        })
    }

    pub(crate) fn analysis(&self) -> Result<&Analysis, ApiError> {
        let analysis = self.analysis.get_or_init(|| {
            let binding = crate::decoder::analysis_binding(&self.binary)?;
            let program = self.discover_through_store(binding.as_deref())?;
            if crate::decoder::analysis_binding(&self.binary)? != binding {
                return Err(DecoderInitializationError::Sleigh(Arc::new(rampage_decompiler::Error::Ghidra(
                    "Project decoder interpretation changed during discovery".into(),
                ))));
            }
            self.analysis_binding.get_or_init(|| binding);
            Ok(Analysis::new(program))
        });
        let analysis = analysis.as_ref().map_err(DecoderInitializationError::to_api_error)?;
        self.finish_store(analysis);
        self.validate_cached_analysis_binding()?;
        Ok(analysis)
    }

    /// Parses `0x` hex or decimal, or looks up a name: the user's, a symbol, export or stub name, an import name
    /// (finding its stub), or `sub_<hex>`.
    pub fn resolve(&self, text: &str) -> Result<u64, ApiError> {
        self.resolve_in(&self.annotations(), text)
    }

    /// A code address as a 32-bit ARM tool needs it. An odd address whose even neighbour is executable Thumb code
    /// (an M-profile image, a Thumb range, or a mode discovery learned there) carries the Thumb bit that vector
    /// tables and function pointers set: bit 0 is cleared, with a note. An odd executable address not known to be
    /// Thumb is kept as given, with a note saying so. Any other address is returned unchanged, without a note.
    pub fn thumb_code_address(&self, address: u64) -> (u64, Option<String>) {
        let even = address & !1;
        let odd_code = self.binary.arch == rampage_arch::Arch::Arm
            && address & 1 == 1
            && self.binary.segment_containing(even).is_some_and(|segment| segment.perms.execute);
        if !odd_code {
            return (address, None);
        }
        let learned = || {
            self.analysis().is_ok_and(|analysis| {
                let modes = &analysis.program.code_modes;
                modes.binary_search_by_key(&even, |&(at, _)| at).is_ok_and(|index| modes[index].1)
            })
        };
        let thumb = self.binary.m_profile() || self.binary.thumb.iter().any(|range| range.contains(&even)) || learned();
        if !thumb {
            let note = format!(
                "{address:#x} has bit 0 set but {even:#x} is not known to be Thumb code: the address was used as                  given; pass an aligned instruction address"
            );
            return (address, Some(note));
        }
        let note = format!(
            "{address:#x} has bit 0 set, the Thumb bit a vector table or function pointer carries: read as the Thumb \
             code at {even:#x}"
        );
        (even, Some(note))
    }

    pub(crate) fn resolve_in(&self, annotations: &Annotations, text: &str) -> Result<u64, ApiError> {
        let text = text.trim();
        if let Some(hex) = hex_address_digits(text) {
            return u64::from_str_radix(hex, 16)
                .map_err(|_| ApiError::Invalid(format!("invalid hex address {text:?}")));
        }
        if let Ok(address) = text.parse() {
            return Ok(address);
        }
        let symbol = self.address_named(annotations, text);
        let peripheral = annotations.peripheral_map().resolve(text);
        if let Some(address) = crate::peripherals::unambiguous(text, symbol, peripheral)? {
            return Ok(address);
        }
        if let Some(address) = default_name_address(text) {
            return Ok(address);
        }
        Err(ApiError::NotFound(format!("no symbol or export named {text:?}")))
    }

    pub fn functions(&self, query: &FunctionsQuery) -> Result<Page<FunctionRow>, ApiError> {
        let analysis = self.analysis()?;
        let annotations = self.annotations();
        let matcher = Matcher::new(query.name_contains.as_deref());
        let selected = analysis.program.functions.iter().filter(|function| {
            matcher.is_everything() || matcher.matches(&self.function_name_in(&annotations, function.address))
        });
        Ok(Page::of(selected, query.offset, query.limit).map(|function| FunctionRow {
            address: function.address,
            name: self.function_name_in(&annotations, function.address),
            size: function.blocks.iter().map(|block| block.end - block.start).sum(),
            blocks: function.blocks.len(),
            instructions: function.instruction_count,
        }))
    }

    /// The start of the function whose block contains `address`, preferring the latest-starting block.
    pub fn function_containing(&self, address: u64) -> Result<Option<u64>, ApiError> {
        Ok(self.analysis()?.function_containing(address))
    }

    /// Hashes, entropy, format details and hints, computed once per project.
    pub fn triage(&self) -> &Triage {
        self.triage.get_or_init(|| {
            let mut triage = triage::triage_with_code(&self.binary, self.code_regions());
            if let Some(raw) = self.binary.raw_code_image() {
                triage.hints.push(raw_triage_note(raw));
            }
            triage
        })
    }

    /// Every code region with its entropy and decode evidence, measured once with the decoder discovery uses, so
    /// a region judged encrypted or packed here is one discovery did not explore.
    pub fn code_regions(&self) -> &[rampage_analysis::code_integrity::CodeRegion] {
        self.code_regions.get_or_init(|| {
            rampage_analysis::code_integrity::assess(&self.binary, || crate::decoder::decoder_for_project(&self.binary))
        })
    }

    /// The code region judged encrypted or packed that holds `address`, if any.
    pub fn encrypted_region_at(&self, address: u64) -> Option<&rampage_analysis::code_integrity::CodeRegion> {
        self.code_regions().iter().find(|region| region.verdict.is_some() && region.contains(address))
    }

    pub fn imports(&self, query: &ListQuery) -> Page<ImportRow> {
        // Slots carry their library on PE and Mach-O, where two libraries may export the same name.
        let slots: HashMap<(Option<&str>, &str), u64> = self
            .binary
            .import_slots
            .iter()
            .map(|slot| ((slot.library.as_deref(), slot.name.as_str()), slot.address))
            .collect();
        let matcher = Matcher::new(query.contains.as_deref());
        let selected = self.binary.imports.iter().filter(|import| {
            matcher.matches(&import.name) || import.library.as_deref().is_some_and(|library| matcher.matches(library))
        });
        Page::of(selected, query.offset, query.limit).map(|import| ImportRow {
            library: import.library.clone(),
            name: import.name.clone(),
            slot: slots
                .get(&(import.library.as_deref(), import.name.as_str()))
                .or_else(|| slots.get(&(None, import.name.as_str())))
                .copied(),
        })
    }

    pub fn exports(&self, query: &ListQuery) -> Page<Export> {
        let matcher = Matcher::new(query.contains.as_deref());
        let selected = self.binary.exports.iter().filter(|export| matcher.matches(&export.name));
        Page::of(selected, query.offset, query.limit).map(Export::clone)
    }

    /// The cached readable strings scanned at the default minimum length, shared by strings queries and
    /// capability detection.
    pub(crate) fn scanned_strings(&self) -> &[FoundString] {
        // Raw images drop runs inside discovered instructions, which runs the (cached) analysis; analysis never
        // reads strings, so this cannot recurse.
        self.strings.get_or_init(|| self.outside_instructions(strings::scan(&self.binary, DEFAULT_STRING_LENGTH)))
    }

    /// The static `{ptr, len}` string headers of a Go image, read once; `None` outside Go images.
    pub(crate) fn go_strings(&self, program: &Program) -> Option<&crate::go_strings::GoStrings> {
        self.binary.go_table.is_some().then(|| {
            self.go_strings.get_or_init(|| crate::go_strings::read(&self.binary, program, self.scanned_strings()))
        })
    }

    /// The Objective-C sends of this project's functions, resolved on first use. Images other than Mach-O with
    /// Objective-C metadata have none, and cost nothing.
    pub(crate) fn objc_dispatch(&self) -> Result<&rampage_analysis::objc_dispatch::Dispatch, ApiError> {
        if let Some(dispatch) = self.objc_dispatch.get() {
            return Ok(dispatch);
        }
        if self.binary.format != rampage_loaders::Format::MachO {
            return Ok(self.objc_dispatch.get_or_init(Default::default));
        }
        let program = &self.analysis()?.program;
        Ok(self.objc_dispatch.get_or_init(|| {
            let report = rampage_loaders::objc::parse(&self.binary);
            rampage_analysis::objc_dispatch::resolve(&self.binary, program, &report, || {
                crate::decoder::decoder_for_project(&self.binary).ok()
            })
        }))
    }

    /// The sends, resolved only when `involved` says the query at hand can involve one (or they already are). The
    /// first query that does resolves every send in the binary, about a tenth of discovery's time.
    pub(crate) fn objc_dispatch_if(
        &self,
        involved: impl FnOnce(&rampage_analysis::objc_dispatch::SendHints) -> bool,
    ) -> Result<Option<&rampage_analysis::objc_dispatch::Dispatch>, ApiError> {
        if let Some(dispatch) = self.objc_dispatch.get() {
            return Ok(Some(dispatch));
        }
        let hints = self.objc_hints.get_or_init(|| {
            if self.binary.format != rampage_loaders::Format::MachO {
                return None;
            }
            let report = rampage_loaders::objc::parse(&self.binary);
            rampage_analysis::objc_dispatch::SendHints::new(&self.binary, &report)
        });
        match hints {
            Some(hints) if involved(hints) => self.objc_dispatch().map(Some),
            _ => Ok(None),
        }
    }

    /// The sends, when the function starting at `start` references a send entry point.
    pub(crate) fn objc_dispatch_for_function(
        &self,
        start: u64,
    ) -> Result<Option<&rampage_analysis::objc_dispatch::Dispatch>, ApiError> {
        let analysis = self.analysis()?;
        let Some(function) = analysis.program.function_at(start) else { return Ok(None) };
        let xrefs = &analysis.program.xrefs;
        let by_source = &analysis.xrefs_by_source;
        self.objc_dispatch_if(|hints| {
            function.blocks.iter().any(|block| {
                let first = by_source.partition_point(|&index| xrefs[index].from < block.start);
                let last = by_source.partition_point(|&index| xrefs[index].from < block.end);
                by_source[first..last].iter().any(|&index| hints.reaches_send(xrefs[index].to))
            })
        })
    }

    /// The embedded DWARF type index, built on first use; the error says why there is none.
    /// The Go runtime type index, built on first use from the type descriptors a Go binary keeps for reflection.
    pub(crate) fn go_types(&self) -> Result<&Arc<rampage_loaders::gotypes::GoTypeIndex>, &str> {
        self.go_types
            .get_or_init(|| rampage_loaders::gotypes::go_type_index(&self.binary).map(Arc::new))
            .as_ref()
            .map_err(String::as_str)
    }

    pub(crate) fn dwarf_types(&self) -> Result<&Arc<rampage_loaders::debug::DwarfTypeIndex>, &str> {
        self.dwarf_types
            .get_or_init(|| rampage_loaders::debug::dwarf_type_index(&self.binary).map(Arc::new))
            .as_ref()
            .map_err(String::as_str)
    }

    /// In a Raw image or Xtensa firmware, whose code regions also hold constants, the strings that overlap no
    /// instruction of a discovered function: printable instruction bytes (Thumb `movs rN, #imm` reads as a character
    /// and a NUL) are not text. Other images, and one whose analysis fails, keep every string.
    fn outside_instructions(&self, found: Vec<FoundString>) -> Vec<FoundString> {
        if self.binary.raw_code_image().is_none() && self.binary.arch != rampage_arch::Arch::Xtensa {
            return found;
        }
        let Ok(analysis) = self.analysis() else { return found };
        let mut blocks: Vec<(u64, u64)> = analysis
            .program
            .functions
            .iter()
            .flat_map(|function| function.blocks.iter().map(|block| (block.start, block.end)))
            .collect();
        blocks.sort_unstable();
        // Merged, so the block before a string's end is the only one that can overlap it.
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(blocks.len());
        for (start, end) in blocks {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        found
            .into_iter()
            .filter(|string| {
                let unit = if string.encoding == strings::Encoding::Utf16Le { 2 } else { 1 };
                let end = string.address + (string.text.chars().count() * unit) as u64;
                let before = merged.partition_point(|&(start, _)| start < end);
                before == 0 || merged[before - 1].1 <= string.address
            })
            .collect()
    }

    pub fn strings(&self, query: &StringsQuery) -> Page<FoundString> {
        let min_len = query.min_len.unwrap_or(DEFAULT_STRING_LENGTH);
        let matcher = Matcher::new(query.contains.as_deref());
        if min_len < DEFAULT_STRING_LENGTH {
            let found = self
                .outside_instructions(strings::scan(&self.binary, min_len))
                .into_iter()
                .filter(|string| matcher.matches(&string.text));
            return Page::of(found, query.offset, query.limit);
        }
        let scanned =
            self.strings.get_or_init(|| self.outside_instructions(strings::scan(&self.binary, DEFAULT_STRING_LENGTH)));
        let selected =
            scanned.iter().filter(|string| string.text.chars().count() >= min_len && matcher.matches(&string.text));
        Page::of(selected, query.offset, query.limit).map(FoundString::clone)
    }

    /// [`Project::strings`] as the list_strings tool returns them: with `contains`, where in each string the text
    /// matches; in a Go image, a long run is flagged as concatenated literals, and a match gets the referenced
    /// literal bounds around it, since Go string data is not NUL-terminated.
    pub fn string_rows(&self, query: &StringsQuery) -> Page<StringRow> {
        let go = self.binary.go_table.is_some();
        let needle = query.contains.as_deref().map(str::to_lowercase).filter(|needle| !needle.is_empty());
        // Go runs are split by the addresses code and static string headers reference, so a Go image needs its
        // (cached) analysis.
        let program = if go { self.analysis().ok().map(|analysis| &analysis.program) } else { None };
        let headers = program.and_then(|program| self.go_strings(program));
        self.strings(query).map(|string| {
            let unit = if string.encoding == strings::Encoding::Utf16Le { 2 } else { 1 };
            let match_address = needle.as_deref().and_then(|needle| {
                let at = string.text.to_lowercase().find(needle)?;
                Some(string.address + (string.text[..at].chars().count() * unit) as u64)
            });
            let end = string.address + (string.text.chars().count() * unit) as u64;
            // A run joins several literals when code or headers reference more than one address inside it.
            let starts: Vec<u64> = program.map_or_else(Vec::new, |program| {
                let first = program.xrefs.partition_point(|xref| xref.to < string.address);
                let last = program.xrefs.partition_point(|xref| xref.to < end);
                let mut starts: Vec<u64> = program.xrefs[first..last]
                    .iter()
                    .filter(|xref| xref.kind == XrefKind::Data)
                    .map(|xref| xref.to)
                    .chain(
                        headers
                            .into_iter()
                            .flat_map(|headers| headers.in_range(string.address, end))
                            .map(|header| header.start),
                    )
                    .collect();
                starts.sort_unstable();
                starts.dedup();
                starts
            });
            let referenced_starts = starts.len();
            let literal = program.zip(match_address).map(|(program, matched)| {
                // The last referenced address at or before the match, and the first after it, bound the literal
                // the match is in; a header's length bounds it exactly.
                let after = starts.partition_point(|&start| start <= matched);
                let start = after.checked_sub(1).map(|index| starts[index]);
                let next = starts.get(after).copied().unwrap_or(end);
                let header = start.and_then(|start| headers?.header(start));
                let header_length = header.and_then(|header| header.length);
                let end = match (start, header_length) {
                    (Some(start), Some(length)) if start + length > matched => start + length,
                    _ => next,
                };
                GoLiteral {
                    start,
                    start_is_match: start == Some(matched),
                    end,
                    start_references: start.map_or(0, |start| {
                        program.xrefs_to(start).len() + header.map_or(0, |header| header.references)
                    }),
                    header_length,
                }
            });
            let blob = referenced_starts > 1;
            StringRow {
                note: blob.then_some(if headers.is_some_and(|headers| headers.truncated) {
                    GO_BLOB_TRUNCATED_NOTE
                } else {
                    GO_BLOB_NOTE
                }),
                match_address,
                go_literal: literal.filter(|_| blob),
                string,
            }
        })
    }
}

const GO_BLOB_NOTE: &str = "Go string data is not NUL-terminated: code references several addresses inside this \
                            run, so it joins several literals. Do not count offsets by hand: use match_address, \
                            go_literal (bounded by addresses code or static string headers reference, exactly by header_length \
                            when a header gives one; when start_is_match is false, start \
                            may begin an earlier literal), or the address and length a referencing instruction or \
                            string header gives.";

const GO_BLOB_TRUNCATED_NOTE: &str = "Go string data is not NUL-terminated: code references several addresses \
                                      inside this run, so it joins several literals. Do not count offsets by \
                                      hand: use match_address, go_literal or a referencing instruction. The static \
                                      string header scan stopped at its cap, so some literal starts are missing.";

/// One list_strings row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StringRow {
    #[serde(flatten)]
    pub string: FoundString,
    /// With `contains`: the address where the text first matches (case-insensitively) inside this string.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub match_address: Option<u64>,
    /// In a Go image with `contains`: the literal around the match, bounded by referenced addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_literal: Option<GoLiteral>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// The bounds of the Go string literal holding a match, from the data references into the run.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct GoLiteral {
    /// The last referenced address at or before the match, inside the run; `null` when none is referenced.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub start: Option<u64>,
    /// Whether `start` is the match itself. Otherwise the match is inside a literal whose own start is not
    /// referenced by code, and `start` may begin an earlier literal.
    pub start_is_match: bool,
    /// The first referenced address after the match inside the run, else the run's end (exclusive); with
    /// `header_length` covering the match, `start` plus that length.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end: u64,
    /// How many references target `start`: instructions and static string headers.
    pub start_references: usize,
    /// The length a static `{ptr, len}` string header in data gives for `start`; `end` is then `start` plus this
    /// length when the match lies inside it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_length: Option<u64>,
}

pub(crate) use rampage_loaders::labels::{check_name, default_name_address, hex_address_digits, is_address_shaped};

#[cfg(test)]
#[path = "debug_layout_import/entry_replay_history_tests.rs"]
mod entry_replay_history_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_analysis::discover::{Block, DiscoveredFunction};
    use rampage_arch::Arch;

    fn raw_cache_fixture() -> Project {
        Project::new(
            Binary::from_raw_code(
                vec![0x60, 0x60],
                rampage_loaders::RawCodeOptions {
                    profile: rampage_loaders::RawProfile::Mos6502,
                    base: 0x1000,
                    entry: None,
                    seeds: vec![0x1000],
                    vector_table: None,
                    pointer_tables: false,
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn metadata_diagnostics_leave_a_cold_raw_analysis_uninitialized() {
        let project = raw_cache_fixture();
        assert!(project.cached_analysis_checked().unwrap().is_none());
        assert!(project.analysis_diagnostics(false).unwrap().discovery.is_none());
        assert!(!project.analysis_cache_status().program);
    }

    #[test]
    fn metadata_diagnostics_refuse_stale_raw_entry_mapping_and_seeds_without_rebuilding() {
        for dimension in 0..3 {
            let mut project = raw_cache_fixture();
            project.analysis().unwrap();
            assert!(project.analysis_diagnostics(false).unwrap().discovery.is_some());
            match dimension {
                0 => project.binary.entry = Some(0x1000),
                1 => project.binary.segments[0].address += 1,
                2 => project.binary.function_starts.push(0x1001),
                _ => unreachable!(),
            }
            assert!(project.cached_analysis_checked().is_err());
            assert!(project.analysis_diagnostics(false).is_err());
            assert!(project.analysis_cache_status().program);
        }
    }

    #[test]
    fn metadata_diagnostics_propagate_a_failed_raw_specification_recheck() {
        let project = raw_cache_fixture();
        project.analysis().unwrap();
        crate::decoder::with_failed_analysis_binding(|| {
            assert!(matches!(project.analysis_diagnostics(false), Err(ApiError::DecoderInitialization(error))
                if error.to_string().contains("injected specification revalidation failure")));
        });
        assert!(project.cached_analysis_checked().unwrap().is_some());
    }

    #[test]
    fn a_cold_checked_accessor_does_not_even_request_raw_specification_revalidation() {
        let project = raw_cache_fixture();
        crate::decoder::with_failed_analysis_binding(|| {
            assert!(project.cached_analysis_checked().unwrap().is_none());
        });
        assert!(!project.analysis_cache_status().program);
    }

    #[test]
    fn an_initialized_discovery_worker_error_is_retained_for_repeated_analysis_reads() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let project = Project::new(Binary::open(path).unwrap());
        let cause = Arc::new(rampage_decompiler::Error::Ghidra("controlled worker initialization failure".into()));
        let opens = AtomicUsize::new(0);
        let memory = rampage_analysis::memory::FlatMemory { base: 0, bytes: vec![0xc3] };
        let initialized = project.analysis.get_or_init(|| {
            let program = rampage_analysis::discover::try_discover(
                &memory,
                || {
                    if opens.fetch_add(1, Ordering::SeqCst) == 0 {
                        rampage_arch::decoder_for(rampage_arch::Arch::X86_64)
                            .map_err(DecoderInitializationError::Unsupported)
                    } else {
                        Err(DecoderInitializationError::Sleigh(Arc::clone(&cause)))
                    }
                },
                &[0],
            )?;
            Ok(Analysis { program, xrefs_by_source: Vec::new(), blocks: Vec::new() })
        });
        assert!(matches!(initialized, Err(DecoderInitializationError::Sleigh(error)) if Arc::ptr_eq(error, &cause)));
        for _ in 0..2 {
            match project.analysis() {
                Err(ApiError::DecoderInitialization(error)) => assert!(Arc::ptr_eq(&error, &cause)),
                _ => panic!("initialized worker error became a different result"),
            }
            assert!(project.cached_analysis().is_none());
            let reads =
                [project.cached_analysis_checked().map(|_| ()), project.analysis_diagnostics(false).map(|_| ())];
            for result in reads {
                match result {
                    Err(ApiError::DecoderInitialization(error)) => assert!(Arc::ptr_eq(&error, &cause)),
                    _ => panic!("non-initializing cached read lost the original initialization failure"),
                }
            }
            assert!(project.analysis_cache_status().program);
        }
        assert_eq!(opens.load(Ordering::SeqCst), 2);
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[allow(dead_code)]
    mod pdb_support {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/pdb/support.rs"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn checked_pdb_late_source_changes_discard_staged_external_edits_but_normal_refresh_still_sees_them() {
        use pdb_support::{TempFiles, fixture, module_stream, stream_offset};

        for source in ["pdb", "image"] {
            let files = TempFiles::new();
            let image = files.write("selected.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
            let original_pdb = std::fs::read(fixture("fixture.pdb")).unwrap();
            let pdb = files.write("selected.pdb", &original_pdb);
            let log = files.write("late-stale.rampage", b"");
            let project =
                Project::with_annotations(Binary::open(&image).unwrap(), Annotations::open(log.clone()).unwrap());
            let mix = 0x140001000;
            let local = 0x140001020;
            project.comment(mix, Some("keep undo")).unwrap();
            project.comment(local, Some("keep redo")).unwrap();
            assert_eq!(project.undo().unwrap()[0].address, local);
            let preview = project.preview_pdb_names(&pdb).unwrap();
            let before_cache = serde_json::to_value(project.annotation_list()).unwrap();

            let state = project.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
            project.validate_pdb_preview(&preview).unwrap();
            let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&project.binary));
            let mut writer = Annotations::open(log.clone()).unwrap();
            writer.set(Field::Name, mix, Some("external_mix".to_owned())).unwrap();
            writer.set(Field::Comment, 0x140005000, Some("external comment".to_owned())).unwrap();
            let external_bytes = std::fs::read(&log).unwrap();
            match source {
                "pdb" => {
                    let mut changed = original_pdb.clone();
                    let start = stream_offset(&original_pdb, module_stream(&original_pdb), 0);
                    let name =
                        original_pdb[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
                    changed[start + name..start + name + 10].copy_from_slice(b"new_local\0");
                    std::fs::write(&pdb, changed).unwrap();
                }
                "image" => {
                    std::fs::OpenOptions::new().write(true).open(&image).unwrap().set_len(1).unwrap();
                }
                _ => unreachable!(),
            }
            // Exercise the same locked commit path used after public apply's successful preflight.
            let error = project.commit_pdb_preview(&preview, &state, &options).unwrap_err();
            drop(state);
            let reason = match source {
                "pdb" => "PDB bytes or provenance changed",
                "image" => "backing file was modified or replaced",
                _ => unreachable!(),
            };
            assert!(error.to_string().contains(reason), "{error}");
            assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before_cache);
            assert_eq!(std::fs::read(&log).unwrap(), external_bytes);
            assert!(project.name_at(mix).is_none());

            assert!(project.refresh_annotations().unwrap());
            assert_eq!(project.name_at(mix).as_deref(), Some("external_mix"));
            assert_eq!(project.comment_at(0x140005000).as_deref(), Some("external comment"));
            assert_eq!(std::fs::read(&log).unwrap(), external_bytes);
            assert_eq!(project.redo().unwrap()[0].address, local);
            assert_eq!(project.undo().unwrap()[0].address, local);
            assert_eq!(project.undo().unwrap()[0].address, mix);
            assert!(project.undo().unwrap().is_empty());
            assert_eq!(project.name_at(mix).as_deref(), Some("external_mix"));
        }
    }

    #[test]
    fn listing_and_graph_reuse_the_analyzed_arm_mode() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let mut binary = Binary::open(path).unwrap();
        let address = binary.entry.unwrap();
        binary.arch = Arch::Arm;
        binary.thumb.clear();
        let project = Project::new(binary);
        let function = DiscoveredFunction {
            address,
            blocks: vec![Block { start: address, end: address + 2 }],
            instruction_count: 1,
            switches: vec![],
        };
        project
            .analysis
            .set(Ok(Analysis {
                program: Program {
                    functions: vec![function],
                    xrefs: vec![],
                    code_modes: vec![(address, true)],
                    resolved_flows: vec![],
                    ..Default::default()
                },
                xrefs_by_source: vec![],
                blocks: vec![BlockSpan {
                    start: address,
                    end: address + 2,
                    function: address,
                    index: 0,
                    reach: address + 2,
                }],
            }))
            .ok()
            .unwrap();
        let listing = project.function_listing(address).unwrap();
        assert_eq!(listing.blocks[0][0].bytes.len(), 4);
        assert_eq!(project.disassemble(Some(&format!("{address:#x}")), 1).unwrap()[0].bytes.len(), 4);
        let graph = project.function_graph(address).unwrap();
        assert_eq!(graph.blocks.len(), 1);
        assert!(graph.edges.is_empty());
    }
}
