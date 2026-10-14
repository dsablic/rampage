use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock, RwLockReadGuard};

use rampage_analysis::discover::Program;
use rampage_analysis::functions::{self, Names};
use rampage_analysis::strings::{self, FoundString};
use rampage_analysis::triage::{self, Triage};
use rampage_arch::UnsupportedArch;
use rampage_loaders::{Binary, Export, ImageAt, LoadError};
use sha2::{Digest, Sha256};

use crate::annotations::{Annotations, Edit, Field};
use crate::rows::{
    Annotation, AnnotationList, EditResult, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Matcher, Page,
    StringsQuery, Summary,
};
use crate::{ApiError, Packs};

/// The shortest string listed unless a query asks for shorter ones.
const DEFAULT_STRING_LENGTH: usize = 4;

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
    pub(crate) annotations: RwLock<Annotations>,
    analysis: OnceLock<Result<Analysis, UnsupportedArch>>,
    triage: OnceLock<Triage>,
    /// Strings of at least `DEFAULT_STRING_LENGTH` characters, scanned once.
    strings: OnceLock<Vec<FoundString>>,
    /// The embedded decompiler, built once over the executable segments on first use. Behind a mutex because
    /// Ghidra's decompiler is not thread-safe and a project is shared across threads.
    pub(crate) decompiler: std::sync::Mutex<crate::decompile::DecompilerState>,
    /// Data packs layered over the bundled heuristic databases.
    packs: RwLock<Arc<Packs>>,
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
    /// The furthest end of this block and every block that starts before it.
    reach: u64,
}

impl Project {
    pub(crate) fn cached_analysis(&self) -> Option<&Analysis> {
        self.analysis.get().and_then(|analysis| analysis.as_ref().ok())
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

    pub fn with_annotations(binary: Binary, annotations: Annotations) -> Self {
        let names = Names::new(&binary);
        Self {
            binary,
            names,
            annotations: RwLock::new(annotations),
            analysis: OnceLock::new(),
            triage: OnceLock::new(),
            strings: OnceLock::new(),
            decompiler: std::sync::Mutex::new(crate::decompile::DecompilerState::default()),
            packs: RwLock::default(),
        }
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
        self.annotations.read().expect("annotations lock")
    }

    /// Picks up edits other processes have saved beside the binary. Returns whether there were any.
    pub fn refresh_annotations(&self) -> Result<bool, ApiError> {
        self.annotations.write().expect("annotations lock").refresh().map_err(ApiError::Invalid)
    }

    /// The name at `address`: the user's, or else a symbol, export, stub or import-slot name.
    pub fn name_at(&self, address: u64) -> Option<String> {
        self.annotations().name(address).map(str::to_owned).or_else(|| self.names.get(address).map(str::to_owned))
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
                    if candidate.globals().is_empty() {
                        return Ok(());
                    }
                    self.validate_annotation_snapshot(&state, &options, candidate)
                })
                .map_err(ApiError::Invalid)
        })?;
        Ok(EditResult { address, field: Field::Name, value, changed })
    }

    /// Previews names from an explicit matching PDB, or applies them as one undoable annotation batch.
    /// Only unnamed, already discovered code-function entries are named; symbols, exports and user names win.
    /// This does not import PDB types, layouts, signatures or undiscovered function starts.
    pub fn import_pdb_names(&self, path: &Path, apply: bool) -> Result<PdbImport, ApiError> {
        let preview = rampage_loaders::pdb::matched_symbols(&self.binary, path)
            .map_err(|error| ApiError::Invalid(error.to_string()))?;
        let mut names = std::collections::BTreeSet::new();
        for function in &preview.functions {
            check_name(&function.name).map_err(ApiError::Invalid)?;
            if !names.insert(&function.name) {
                return Err(ApiError::Invalid("ambiguous PDB name at multiple addresses; nothing imported".to_owned()));
            }
        }
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
                    if candidate.globals().is_empty() {
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
        let mut names = std::collections::BTreeSet::new();
        for function in &report.functions {
            check_name(&function.name).map_err(ApiError::Invalid)?;
            if !names.insert(&function.name) {
                return Err(ApiError::Invalid("ambiguous PDB name at multiple addresses; nothing imported".to_owned()));
            }
        }
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
                        let result = if candidate.globals().is_empty() {
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
        self.annotations
            .write()
            .expect("annotations lock")
            .undo_validated(|candidate| {
                if candidate.types().is_empty() && candidate.signatures().is_empty() && candidate.globals().is_empty() {
                    return Ok(());
                }
                self.validate_annotation_snapshot(&state, &options, candidate)
            })
            .map_err(ApiError::Invalid)
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
        self.annotations
            .write()
            .expect("annotations lock")
            .redo_validated(|candidate| {
                if candidate.types().is_empty() && candidate.signatures().is_empty() && candidate.globals().is_empty() {
                    return Ok(());
                }
                self.validate_annotation_snapshot(&state, &options, candidate)
            })
            .map_err(ApiError::Invalid)
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
        }
    }

    pub fn summary(&self) -> Summary<'_> {
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
        }
    }

    pub(crate) fn analysis(&self) -> Result<&Analysis, ApiError> {
        let analysis = self.analysis.get_or_init(|| {
            let program = functions::analyze(&self.binary)?;
            let mut blocks: Vec<BlockSpan> = program
                .functions
                .iter()
                .flat_map(|function| {
                    function.blocks.iter().map(|block| BlockSpan {
                        start: block.start,
                        end: block.end,
                        function: function.address,
                        reach: 0,
                    })
                })
                .collect();
            blocks.sort_unstable_by_key(|block| (block.start, block.end, block.function));
            let mut reach = 0;
            for block in &mut blocks {
                reach = reach.max(block.end);
                block.reach = reach;
            }
            let mut xrefs_by_source: Vec<usize> = (0..program.xrefs.len()).collect();
            xrefs_by_source.sort_unstable_by_key(|&index| (program.xrefs[index].from, program.xrefs[index].to));
            Ok(Analysis { program, xrefs_by_source, blocks })
        });
        analysis.as_ref().map_err(|&error| ApiError::Unsupported(error))
    }

    /// Parses `0x` hex or decimal, or looks up a name: the user's, a symbol, export or stub name, an import name
    /// (finding its stub), or `sub_<hex>`.
    pub fn resolve(&self, text: &str) -> Result<u64, ApiError> {
        self.resolve_in(&self.annotations(), text)
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
        if let Some(address) = self.address_named(annotations, text) {
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
        let blocks = &self.analysis()?.blocks;
        let candidates = blocks.partition_point(|block| block.start <= address);
        Ok(blocks[..candidates]
            .iter()
            .rev()
            .take_while(|block| block.reach > address)
            .find(|block| address < block.end)
            .map(|block| block.function))
    }

    /// Hashes, entropy, format details and hints, computed once per project.
    pub fn triage(&self) -> &Triage {
        self.triage.get_or_init(|| triage::triage(&self.binary))
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
        self.strings.get_or_init(|| strings::scan(&self.binary, DEFAULT_STRING_LENGTH))
    }

    pub fn strings(&self, query: &StringsQuery) -> Page<FoundString> {
        let min_len = query.min_len.unwrap_or(DEFAULT_STRING_LENGTH);
        let matcher = Matcher::new(query.contains.as_deref());
        if min_len < DEFAULT_STRING_LENGTH {
            let found = strings::scan(&self.binary, min_len).into_iter().filter(|string| matcher.matches(&string.text));
            return Page::of(found, query.offset, query.limit);
        }
        let scanned = self.strings.get_or_init(|| strings::scan(&self.binary, DEFAULT_STRING_LENGTH));
        let selected =
            scanned.iter().filter(|string| string.text.chars().count() >= min_len && matcher.matches(&string.text));
        Page::of(selected, query.offset, query.limit).map(FoundString::clone)
    }
}

/// Refuses a name that is not an identifier, or that `resolve` would read as an address. `resolve` parses `0x...`
/// and `0X...` before looking up names, so such a name could never be looked up. It looks up names before
/// `sub_<hex>`, so naming one function `sub_401000` would shadow the default name of the function at 0x401000.
/// Other names that merely start with `sub_` (`sub_menu_init`) are fine.
pub(crate) fn check_name(name: &str) -> Result<(), String> {
    // Before the identifier rules, which refuse `0x...` too but with a less helpful reason.
    if is_address_shaped(name) {
        return Err(format!("{name:?} looks like an address; choose another name"));
    }
    let valid = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.$@?:".contains(c));
    if !valid {
        return Err(format!("{name:?} is not a valid name: use letters, digits and _.$@?:"));
    }
    Ok(())
}

pub(crate) fn is_address_shaped(name: &str) -> bool {
    hex_address_digits(name).is_some() || default_name_address(name).is_some()
}

/// The hex digits of an address written `0x...` or `0X...`, as `resolve` reads it.
fn hex_address_digits(text: &str) -> Option<&str> {
    text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
}

/// The address in a default function name `sub_<hex>`, as `resolve` reads it.
fn default_name_address(text: &str) -> Option<u64> {
    text.strip_prefix("sub_").and_then(|hex| u64::from_str_radix(hex, 16).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_analysis::discover::{Block, DiscoveredFunction};
    use rampage_arch::Arch;

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
                blocks: vec![BlockSpan { start: address, end: address + 2, function: address, reach: address + 2 }],
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
