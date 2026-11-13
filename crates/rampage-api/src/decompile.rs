//! C decompilation of a function, through the embedded Ghidra decompiler (`rampage-decompiler`). The decompiler
//! is built once per project over its executable segments and reused for every function.

mod context;
mod entry;
mod entry_plan;
mod go_abi;
mod image;
mod isolated;
mod symbols;
mod types;

use rampage_decompiler::{Decompiler, DecompilerOptions, Platform};
use serde::Serialize;
use std::sync::{Arc, TryLockError};

use crate::{ApiError, Project};

pub(crate) fn validate_declaration_input(text: &str) -> Result<(), ApiError> {
    types::validate(text)
}

pub use entry::{
    DecompileEntryOrigin, DecompileEntryRequest, EntryContextCounts, EntryDecompilation, EntryDecompilationContext,
    EntryPreparationPhase, EntryPreparationProgress, EntryPreparationTimings, EntryValidation,
};

/// A process-local configuration identity. Returning to earlier settings does not restore an old identity.
#[derive(Debug, Clone)]
pub struct DecompilerConfigurationRevision(Arc<()>);

impl PartialEq for DecompilerConfigurationRevision {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for DecompilerConfigurationRevision {}

pub(crate) use go_abi::GoPrototypes;
pub(crate) use isolated::query_types as isolated_type_query;
pub(crate) use symbols::posix_context;
pub(crate) use symbols::stub_targets as import_stub_targets;
pub(crate) use types::declaration_tokens as type_tokens;
pub(crate) use types::validate_local_type;

#[derive(Clone, Copy, Default)]
pub(crate) struct NativeDecompileContext<'a> {
    pub operations: &'a [rampage_decompiler::worker::WorkerOperation],
    pub admitted: Option<&'a std::collections::BTreeSet<u64>>,
    pub cancellation: Option<&'a std::sync::atomic::AtomicBool>,
}

pub(crate) fn hint_context_error(message: &str) -> Option<ApiError> {
    let message = message.strip_prefix("decompiler: ").unwrap_or(message);
    let retention_refusal = "Unsupported native soft hint: unlocked type was not retained by analysis";
    if message == retention_refusal {
        return Some(ApiError::NativeTypeHintUnsupported(message.to_owned()));
    }
    let reason = message.strip_prefix("Unsupported native callee hint context: ")?;
    let known_refusal = matches!(
        reason,
        "Unsupported native hint: whole symbol mapping did not survive"
            | "Local variable storage selector did not match a recovered symbol"
    );
    (known_refusal || reason == retention_refusal).then(|| ApiError::NativeTypeHintUnsupported(message.to_owned()))
}

fn native_decompile_error(error: rampage_decompiler::Error) -> ApiError {
    if let rampage_decompiler::Error::Ghidra(message) = &error
        && let Some(refusal) = hint_context_error(message)
    {
        return refusal;
    }
    ApiError::Unavailable(error.to_string())
}

#[derive(Debug, Serialize)]
pub struct Decompilation {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    /// The decompiled function as C source.
    pub code: String,
    /// Exact processor/compiler specification used for this result.
    pub language_id: String,
    pub tokens: Vec<DecompiledToken>,
    #[serde(serialize_with = "serialize_structure")]
    pub structure: rampage_decompiler::StructuredResult,
    pub recovery_status: rampage_decompiler::results::RecoveryStatus,
    pub variables: Vec<crate::VariableDescriptor>,
}

fn serialize_structure<S: serde::Serializer>(
    structure: &rampage_decompiler::StructuredResult,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    fn addresses(value: &mut serde_json::Value, key: Option<&str>) {
        match value {
            serde_json::Value::Number(number)
                if matches!(
                    key,
                    Some("address" | "start" | "end" | "source" | "target" | "switch_address" | "global_address")
                ) =>
            {
                if let Some(address) = number.as_u64() {
                    *value = serde_json::Value::String(format!("{address:#x}"));
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    addresses(item, if key == Some("targets") { Some("target") } else { key });
                }
            }
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    addresses(value, Some(key));
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(structure).map_err(serde::ser::Error::custom)?;
    addresses(&mut value, None);
    value.serialize(serializer)
}

#[derive(Debug, Serialize)]
pub struct DecompiledToken {
    pub text: String,
    pub kind: String,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub address: Option<u64>,
    pub span: Option<(usize, usize)>,
}

#[derive(Default)]
pub(crate) struct DecompilerState {
    pub(crate) options: Option<DecompilerOptions>,
    engine: Option<Decompiler>,
    /// Raw interpretation the cached engine maps; other interpretations never reuse its image or C.
    engine_interpretation: Option<String>,
    names: std::collections::BTreeMap<u64, String>,
    signatures: std::collections::BTreeMap<u64, String>,
    types: std::collections::BTreeMap<u64, String>,
    type_library: std::collections::BTreeMap<u64, String>,
    debug_types: std::collections::BTreeMap<u64, String>,
    globals: std::collections::BTreeMap<u64, String>,
    data_types: std::collections::BTreeMap<u64, String>,
    local_names: std::collections::BTreeMap<u64, String>,
    local_types: std::collections::BTreeMap<u64, String>,
    type_hints: std::collections::BTreeMap<u64, String>,
    hint_address: Option<u64>,
    pub(crate) propagation_cache: Option<crate::propagation::LazyContext>,
    pub(crate) worker: Option<rampage_decompiler::worker::WorkerConfig>,
    configuration_revision: Arc<()>,
}

pub(crate) fn default_options(binary: &rampage_loaders::Binary) -> DecompilerOptions {
    let platform = match binary.format {
        rampage_loaders::Format::Pe => Platform::Windows,
        rampage_loaders::Format::MachO => Platform::Darwin,
        rampage_loaders::Format::Elf | rampage_loaders::Format::Snapshot => Platform::Default,
        rampage_loaders::Format::Raw => Platform::Default,
    };
    let (platform, compiler) = binary.snapshot_target.as_ref().map_or((platform, None), |context| {
        let platform = match context.platform {
            rampage_loaders::snapshot::SnapshotPlatform::Default => Platform::Default,
            rampage_loaders::snapshot::SnapshotPlatform::Darwin => Platform::Darwin,
            rampage_loaders::snapshot::SnapshotPlatform::Windows => Platform::Windows,
        };
        (platform, context.compiler.clone())
    });
    let arm_be8 = if binary.arch == rampage_arch::Arch::Arm {
        let target = binary.target();
        target.data_big_endian && !target.big_endian
    } else {
        false
    };
    DecompilerOptions { platform, compiler: compiler.or_else(|| go_compiler(binary)), arm_be8 }
}

/// Go's register ABI for a binary whose pclntab proves it. Go passes arguments in registers from go1.17 on
/// x86-64 and go1.18 on AArch64; read as C, those calls lose their arguments and the code computing them. A
/// go1.18+ table proves the register ABI on both. A go1.16 table also covers go1.17, and older Go passed
/// arguments on the stack, so those keep the platform default rather than guess.
fn go_compiler(binary: &rampage_loaders::Binary) -> Option<String> {
    use rampage_loaders::gopclntab::GoTableVersion;
    let register_abi = matches!(binary.go_table, Some(GoTableVersion::Go118 | GoTableVersion::Go120));
    let supported = matches!(binary.arch, rampage_arch::Arch::X86_64 | rampage_arch::Arch::Aarch64);
    (register_abi && supported && !binary.big_endian).then(|| "golang".to_owned())
}

pub(crate) fn validate_cached_layout_source(project: &Project, state: &DecompilerState) -> Result<(), ApiError> {
    if !state.debug_types.is_empty()
        || state.types.values().chain(state.signatures.values()).any(|text| text.starts_with('!'))
    {
        crate::debug_layout_import::check_backing(project)?;
    }
    Ok(())
}

impl Project {
    pub(crate) fn native_type_context(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        annotations: &crate::annotations::Annotations,
        cancellation: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<(String, rampage_decompiler::DataOrganization), ApiError> {
        if let Some(config) = &state.worker {
            let never_cancelled = std::sync::atomic::AtomicBool::new(false);
            let output = isolated::query_types_cancellable(
                self,
                annotations,
                options,
                config,
                rampage_decompiler::worker::TypeQuery::Inventory,
                &[],
                cancellation.unwrap_or(&never_cancelled),
            )?;
            Ok((
                output.language_id,
                rampage_decompiler::DataOrganization {
                    pointer: output.data_organization.pointer,
                    int: output.data_organization.int,
                    long: output.data_organization.long,
                },
            ))
        } else {
            let engine = self.build_decompiler(options, annotations)?;
            Ok((engine.language_id().to_owned(), engine.data_organization()))
        }
    }
    /// Reads configured overrides without constructing an engine, deriving defaults or reading mapped bytes.
    pub fn configured_decompiler_options(&self) -> Result<Option<DecompilerOptions>, ApiError> {
        let state = match self.decompiler.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(ApiError::Unavailable("decompiler configuration is busy".into()));
            }
        };
        Ok(state.options.clone())
    }

    /// Nonblocking local identity check; it does not attest specification validity or authorize native work.
    pub fn decompiler_configuration_revision(&self) -> Result<DecompilerConfigurationRevision, ApiError> {
        let state = match self.decompiler.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(ApiError::Unavailable("decompiler configuration is busy".into()));
            }
        };
        Ok(DecompilerConfigurationRevision(Arc::clone(&state.configuration_revision)))
    }

    pub(crate) fn validate_annotation_snapshot(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        candidate: &crate::annotations::Annotations,
    ) -> Result<(), String> {
        self.validate_patch_context(candidate).map_err(|error| error.to_string())?;
        validate_cached_layout_source(self, state).map_err(|error| error.to_string())?;
        crate::debug_layout_import::validate_replay_source(self, candidate).map_err(|error| error.to_string())?;
        crate::debug_type_import::validate_replay_source(self, candidate).map_err(|error| error.to_string())?;
        crate::debug_type_import::validate_options(candidate, options).map_err(|error| error.to_string())?;
        self.validate_type_library_snapshot(state, options, candidate).map_err(|error| error.to_string())?;
        if !candidate.data_types().is_empty() || !candidate.operand_types().is_empty() {
            let mut names = crate::typed_data::binding_names(candidate).map_err(|error| error.to_string())?;
            names.extend(crate::operand_types::binding_names(candidate).map_err(|error| error.to_string())?);
            names.sort();
            names.dedup();
            let types = self.native_data_types(state, options, candidate, &names).map_err(|error| error.to_string())?;
            crate::typed_data::validate_bindings(self, candidate, &types).map_err(|error| error.to_string())?;
            crate::operand_types::validate_operand_annotations(self, candidate, &types)
                .map_err(|error| error.to_string())?;
        }
        let mut targets = crate::variables::targets(candidate);
        targets.extend(
            crate::propagation::replay_hints(self, options, candidate, None)
                .map_err(|error| error.to_string())?
                .0
                .keys()
                .copied(),
        );
        if !targets.is_empty() {
            for address in targets {
                self.decompile_annotation_candidate(state, options, candidate, address)
                    .map_err(|error| format!("validate native annotation target {address:#x}: {error}"))?;
            }
            return Ok(());
        }
        if candidate.types().is_empty()
            && candidate.type_library().is_empty()
            && candidate.debug_types().is_empty()
            && candidate.signatures().is_empty()
            && candidate.globals().is_empty()
            && candidate.data_types().is_empty()
            && candidate.operand_types().is_empty()
        {
            return Ok(());
        }
        if let Some(config) = &state.worker {
            return isolated::decompile(
                self,
                candidate,
                options,
                config,
                None,
                &std::sync::atomic::AtomicBool::new(false),
            )
            .map(|_| ())
            .map_err(|error| error.to_string());
        }
        self.build_decompiler(options, candidate).map(|_| ()).map_err(|error| error.to_string())
    }
    /// Whether native decompilation runs in a supervised worker process (true) or in this process (false).
    pub fn decompiles_in_worker(&self) -> bool {
        self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner()).worker.is_some()
    }
    /// Enables supervised child-process decompilation. No in-process fallback occurs when the worker fails.
    pub fn set_decompiler_worker(&self, config: Option<rampage_decompiler::worker::WorkerConfig>) {
        let mut state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        state.engine = None;
        state.worker = config;
        state.propagation_cache = None;
        state.configuration_revision = Arc::new(());
    }
    /// Stores one address-bound C signature, including an optional calling convention such as __cdecl.
    pub fn set_signature(&self, address: u64, declaration: Option<&str>) -> Result<crate::EditResult, ApiError> {
        let address = if self.binary.import_slot(address).is_some() {
            address
        } else {
            self.function_containing(address)?.unwrap_or(address)
        };
        crate::debug_layout_import::validate_replay_source(self, &self.annotations())?;
        self.set_type_annotation(crate::annotations::Field::Signature, address, declaration)
    }

    /// Stores ordered typedef/struct/union/enum declarations associated with an address.
    /// Comments, preprocessor directives and quoted literals are not accepted by this bounded declaration input.
    pub fn set_types(&self, address: u64, declarations: Option<&str>) -> Result<crate::EditResult, ApiError> {
        self.set_type_annotation(crate::annotations::Field::Types, address, declarations)
    }

    pub fn set_global(&self, address: u64, declaration: Option<&str>) -> Result<crate::EditResult, ApiError> {
        if declaration.is_some()
            && (self.binary.is_code(address) || !self.binary.segments.iter().any(|segment| segment.contains(address)))
        {
            return Err(ApiError::Invalid("global address requires mapped data, not code".to_owned()));
        }
        self.set_type_annotation(crate::annotations::Field::Global, address, declaration)
    }

    fn set_type_annotation(
        &self,
        field: crate::annotations::Field,
        address: u64,
        value: Option<&str>,
    ) -> Result<crate::EditResult, ApiError> {
        use crate::annotations::Field;
        let value = value.map(str::trim).filter(|value| !value.is_empty());
        if let Some(value) = value {
            validate_declaration_input(value)?;
        }
        if field == Field::Signature
            && value.is_some()
            && !self.binary.is_code(address)
            && self.binary.import_slot(address).is_none()
        {
            return Err(ApiError::Invalid("signature address is neither code nor an import slot".to_owned()));
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        crate::debug_layout_import::validate_replay_source(self, &self.annotations())?;
        let options = state.options.clone().unwrap_or_else(|| default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        let value = value.map(str::to_owned);
        let changed = annotations.locked_staged_checked(|current| {
            self.validate_patch_context(current)?;
            crate::debug_layout_import::validate_replay_source(self, current)?;
            current
                .set_validated(field, address, value.clone(), |candidate| {
                    self.validate_annotation_snapshot(&state, &options, candidate)
                })
                .map_err(ApiError::Invalid)
        })?;
        Ok(crate::EditResult { address, field, value, changed })
    }

    /// Overrides automatic format-based compiler selection. `None` restores automatic selection.
    /// Invalid specifications return an error on the next decompilation, never fall back silently.
    pub fn set_decompiler_options(&self, mut options: Option<DecompilerOptions>) {
        if default_options(&self.binary).arm_be8
            && let Some(options) = &mut options
        {
            options.arm_be8 = true;
        }
        let mut state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        state.engine = None;
        state.options = options;
        state.propagation_cache = None;
        state.configuration_revision = Arc::new(());
    }

    /// Validates the selected compiler and remaining annotations before publishing new options.
    /// Unlike `set_decompiler_options`, a rejected selection leaves the current options and cache intact.
    pub fn try_set_decompiler_options(&self, mut options: Option<DecompilerOptions>) -> Result<(), ApiError> {
        if default_options(&self.binary).arm_be8
            && let Some(options) = &mut options
        {
            options.arm_be8 = true;
        }
        let selected = options.clone().unwrap_or_else(|| default_options(&self.binary));
        let mut state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        validate_cached_layout_source(self, &state)?;
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|candidate| {
            self.validate_patch_context(candidate)?;
            validate_cached_layout_source(self, &state)?;
            crate::debug_layout_import::validate_replay_source(self, candidate)?;
            if !crate::variables::targets(candidate).is_empty() || !candidate.data_types().is_empty() {
                self.validate_annotation_snapshot(&state, &selected, candidate).map_err(ApiError::Invalid)?;
            } else if let Some(config) = &state.worker {
                isolated::decompile(
                    self,
                    candidate,
                    &selected,
                    config,
                    None,
                    &std::sync::atomic::AtomicBool::new(false),
                )?;
            } else {
                self.build_decompiler(&selected, candidate)?;
            }
            crate::debug_layout_import::validate_replay_source(self, candidate)?;
            state.engine = None;
            state.options = options;
            state.propagation_cache = None;
            state.configuration_revision = Arc::new(());
            Ok(())
        })
    }

    /// Decompiles the function containing `address` to C using bundled processor specifications.
    /// Explicit typing inputs trigger read-only lazy derivation over at most eight context functions;
    /// unsupported native directions are reported rather than converted into hard user overrides.
    /// `propagate_types` with `apply=true` is the separate durable annotation operation.
    pub fn decompile(&self, address: u64) -> Result<Decompilation, ApiError> {
        self.decompile_cancellable(address, &std::sync::atomic::AtomicBool::new(false))
    }

    pub fn decompile_cancellable(
        &self,
        address: u64,
        cancellation: &std::sync::atomic::AtomicBool,
    ) -> Result<Decompilation, ApiError> {
        if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ApiError::Unavailable("decompilation cancelled".to_owned()));
        }
        let mut slot = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ApiError::Unavailable("decompilation cancelled".to_owned()));
        }
        validate_cached_layout_source(self, &slot)?;
        let annotations = {
            let current = self.annotations();
            crate::debug_layout_import::validate_replay_source(self, &current)?;
            current.snapshot()
        };
        crate::debug_layout_import::validate_replay_source(self, &annotations)?;
        let start = self.function_containing(address)?.unwrap_or(address);
        crate::debug_layout_import::validate_replay_source(self, &annotations)?;
        if let Some(region) = self.encrypted_region_at(start) {
            return Err(ApiError::Invalid(format!(
                "{start:#x} lies in code judged encrypted or packed, so decompiling it would only produce noise: {}",
                region.explain()
            )));
        }
        if self.binary.code_from(start).is_none() {
            return Err(ApiError::Invalid("decompilation requires a file-backed code address".to_owned()));
        }
        let options = slot.options.clone().unwrap_or_else(|| default_options(&self.binary));
        crate::debug_type_import::validate_replay_source(self, &annotations)?;
        crate::debug_type_import::validate_options(&annotations, &options)?;
        let (annotations, automatic_limitations) =
            crate::propagation::lazy_context(self, &mut slot, &options, &annotations, start, cancellation)?;
        let name = self.function_name_in(&annotations, start);
        if let Some(config) = slot.worker.clone() {
            let options = slot.options.clone().unwrap_or_else(|| default_options(&self.binary));
            if !annotations.data_types().is_empty() {
                let names = crate::typed_data::binding_names(&annotations)?;
                let types = self.native_data_types(&slot, &options, &annotations, &names)?;
                crate::typed_data::validate_bindings(self, &annotations, &types)?;
            }
            drop(slot);
            let mut result =
                isolated::decompile(self, &annotations, &options, &config, Some((start, name)), cancellation)?;
            crate::propagation::append_limitations(&mut result.structure, automatic_limitations);
            result.recovery_status = result.structure.recovery_status();
            return Ok(result);
        }
        if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ApiError::Unavailable("decompilation cancelled".to_owned()));
        }
        let interpretation = self
            .binary
            .raw_interpretation_identity()
            .map_err(|error| ApiError::Invalid(format!("decompilation Raw identity unavailable: {error}")))?
            .map(|identity| format!("{}:{}", identity.schema, identity.sha256));
        if slot.engine_interpretation != interpretation || slot.names != *annotations.names() {
            slot.engine = None;
        }
        if slot.signatures != *annotations.signatures()
            || slot.types != *annotations.types()
            || slot.type_library != *annotations.type_library()
            || slot.debug_types != *annotations.debug_types()
            || slot.globals != *annotations.globals()
            || slot.data_types != *annotations.data_types()
            || slot.local_names != *annotations.local_names()
            || slot.local_types != *annotations.local_types()
            || slot.type_hints != *annotations.type_hints()
        {
            slot.engine = None;
        }
        if slot.hint_address != Some(start)
            && (!annotations.local_types().is_empty() || !annotations.type_hints().is_empty())
        {
            slot.engine = None;
        }
        if slot.engine.is_none() {
            let options = slot.options.clone().unwrap_or_else(|| default_options(&self.binary));
            slot.engine =
                Some(self.build_decompiler_with_operations(&options, &annotations, &[], Some(start), None)?);
            slot.hint_address = Some(start);
            slot.engine_interpretation = interpretation;
            slot.names = annotations.names().clone();
            slot.signatures = annotations.signatures().clone();
            slot.types = annotations.types().clone();
            slot.type_library = annotations.type_library().clone();
            slot.debug_types = annotations.debug_types().clone();
            slot.globals = annotations.globals().clone();
            slot.data_types = annotations.data_types().clone();
            slot.local_names = annotations.local_names().clone();
            slot.local_types = annotations.local_types().clone();
            slot.type_hints = annotations.type_hints().clone();
        }
        let options = slot.options.clone().unwrap_or_else(|| default_options(&self.binary));
        let decompiler = slot.engine.as_mut().expect("just built");
        let thumb = if self.binary.arch == rampage_arch::Arch::Arm {
            context::mode_at(&self.binary.target(), &self.analysis()?.program.code_modes, start)
        } else {
            false
        };
        if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ApiError::Unavailable("decompilation cancelled".to_owned()));
        }
        let code = decompiler.decompile(start, &name, thumb).map_err(native_decompile_error)?;
        crate::debug_layout_import::validate_replay_source(self, &annotations)?;
        crate::debug_type_import::validate_replay_source(self, &annotations)?;
        let tokens = decompiler
            .tokens()
            .into_iter()
            .map(|token| DecompiledToken {
                text: token.text,
                kind: token.kind,
                address: token.address,
                span: token.span,
            })
            .collect();
        let mut structure = decompiler.structured_result().map_err(|error| ApiError::Unavailable(error.to_string()))?;
        crate::propagation::validate_replayed_targets(self, &options, &annotations, start, &structure)?;
        let (_, limitations) = crate::propagation::replay_hints(self, &options, &annotations, Some(start))?;
        crate::propagation::append_limitations(&mut structure, limitations);
        crate::propagation::append_limitations(&mut structure, automatic_limitations);
        let variables = crate::variables::descriptors(&structure);
        Ok(Decompilation {
            address: start,
            name,
            code,
            language_id: decompiler.language_id().to_owned(),
            tokens,
            recovery_status: structure.recovery_status(),
            structure,
            variables,
        })
    }

    /// Builds a decompiler over the program's loadable segments and registers the names rampage knows, so calls
    /// render by name. Read-only segments are mapped read-only; loads from them fold into constants only on Cortex-M
    /// Raw images (`FoldReadOnly`), since a headered image's read-only sections can be written at run time.
    pub(crate) fn build_decompiler(
        &self,
        options: &DecompilerOptions,
        annotations: &crate::annotations::Annotations,
    ) -> Result<Decompiler, ApiError> {
        self.build_decompiler_with_operations(options, annotations, &[], None, None)
    }

    pub(crate) fn build_decompiler_with_operations(
        &self,
        options: &DecompilerOptions,
        annotations: &crate::annotations::Annotations,
        extra_operations: &[rampage_decompiler::worker::WorkerOperation],
        hint_function: Option<u64>,
        hint_context: Option<&std::collections::BTreeSet<u64>>,
    ) -> Result<Decompiler, ApiError> {
        crate::debug_type_import::validate_replay_source(self, annotations)?;
        crate::debug_type_import::validate_options(annotations, options)?;
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        let binary = &self.binary;
        let regions = image::regions(binary)?;
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        // A segment can hold more than code (a Mach-O __TEXT starts with headers), so require an executable
        // segment rather than one that begins at code.
        if !binary.segments.iter().any(|segment| segment.perms.execute && segment.file_size > 0) {
            return Err(ApiError::Unavailable("no executable segments to decompile".to_owned()));
        }
        let mut decompiler = Decompiler::open_with_options(binary.arch, binary.big_endian, &regions, options)
            .map_err(|error| ApiError::Unavailable(error.to_string()))?;
        crate::type_library::validate_profile_replay(
            annotations,
            options,
            decompiler.data_organization(),
            decompiler.language_id(),
        )?;
        if binary.arch == rampage_arch::Arch::Arm {
            let modes = context::arm_points(binary, &self.analysis()?.program.code_modes);
            decompiler.set_code_modes(&modes).map_err(|error| ApiError::Unavailable(error.to_string()))?;
        }

        let mut operations = symbols::plan(self, annotations)?;
        symbols::specialize_imports(
            annotations,
            options,
            decompiler.language_id(),
            decompiler.data_organization(),
            &mut operations,
        )?;
        let go = go_abi::plan(self, annotations, options);
        operations.extend(types::plan(self, annotations, &go.types)?);
        operations.extend(go.prototypes);
        operations.extend(crate::variables::plan(self, annotations, None)?);
        operations.extend(if let Some(context) = hint_context {
            crate::propagation::hint_operations_in_context(self, options, annotations, context)?
        } else {
            crate::propagation::hint_operations(self, options, annotations, hint_function)?
        });
        operations.extend_from_slice(extra_operations);
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        symbols::apply(operations, &mut decompiler)?;
        let data_types = crate::typed_data::binding_names(annotations)?
            .into_iter()
            .map(|name| decompiler.get_type(&name).map_err(|error| ApiError::Invalid(error.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        crate::typed_data::validate_bindings(self, annotations, &data_types)?;
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        Ok(decompiler)
    }

    /// Queries a bounded native graph against one immutable annotation/options snapshot. Worker failures never
    /// fall back in-process; the in-process path uses one fresh engine for every reference in the graph.
    pub(crate) fn native_data_types(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        annotations: &crate::annotations::Annotations,
        names: &[String],
    ) -> Result<Vec<rampage_decompiler::NamedType>, ApiError> {
        use std::collections::{BTreeMap, BTreeSet};
        validate_cached_layout_source(self, state)?;
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        let mut pending: BTreeSet<String> = names.iter().cloned().collect();
        let mut types = BTreeMap::new();
        let mut identity_nodes = 0usize;
        let engine = if state.worker.is_none() { Some(self.build_decompiler(options, annotations)?) } else { None };
        let mut worker_queries = 0usize;
        let mut catalog: BTreeMap<String, rampage_decompiler::NamedType> = if let Some(config) = &state.worker {
            worker_queries += 1;
            isolated_type_query(
                self,
                annotations,
                options,
                config,
                rampage_decompiler::worker::TypeQuery::Inventory,
                &[],
            )?
            .type_inventory
            .ok_or_else(|| ApiError::Unavailable("worker omitted native data type catalog".into()))?
            .into_iter()
            .map(|ty| (ty.name.clone(), ty))
            .collect()
        } else {
            BTreeMap::new()
        };
        while let Some(name) = pending.pop_first() {
            if types.contains_key(&name) {
                continue;
            }
            if types.len() >= 64 {
                return Err(ApiError::Invalid("native data type query budget exceeds 64 names".into()));
            }
            let ty = if let Some(config) = &state.worker {
                if let Some(ty) = catalog.remove(&name) {
                    ty
                } else {
                    worker_queries += 1;
                    if worker_queries > 64 {
                        return Err(ApiError::Invalid("native data type query budget exceeds 64 queries".into()));
                    }
                    let output = isolated_type_query(
                        self,
                        annotations,
                        options,
                        config,
                        rampage_decompiler::worker::TypeQuery::Get { name: name.clone() },
                        &[],
                    )?;
                    output
                        .type_inventory
                        .and_then(|types| types.into_iter().find(|ty| ty.name == name))
                        .ok_or_else(|| ApiError::Unavailable("worker omitted requested native data type".into()))?
                }
            } else {
                engine
                    .as_ref()
                    .expect("in-process type engine")
                    .get_type(&name)
                    .map_err(|error| ApiError::Invalid(error.to_string()))?
            };
            if let Some(identity) = &ty.identity {
                crate::typed_data::identity_references(identity, &mut pending, 0, &mut identity_nodes)?;
            }
            types.insert(name, ty);
            pending.retain(|name| !types.contains_key(name));
        }
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        Ok(types.into_values().collect())
    }

    pub(crate) fn decompile_annotation_candidate(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        annotations: &crate::annotations::Annotations,
        address: u64,
    ) -> Result<Decompilation, ApiError> {
        self.decompile_annotation_candidate_with_operations(
            state,
            options,
            annotations,
            address,
            NativeDecompileContext::default(),
        )
    }

    pub(crate) fn decompile_annotation_candidate_with_operations(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        annotations: &crate::annotations::Annotations,
        address: u64,
        context: NativeDecompileContext<'_>,
    ) -> Result<Decompilation, ApiError> {
        self.validate_patch_context(annotations)?;
        let never_cancelled = std::sync::atomic::AtomicBool::new(false);
        let cancellation = context.cancellation.unwrap_or(&never_cancelled);
        if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ApiError::Unavailable("decompilation cancelled".into()));
        }
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        if self.binary.code_from(address).is_none() {
            return Err(ApiError::Invalid("local overrides require a file-backed function entry".to_owned()));
        }
        let name = self.function_name_in(annotations, address);
        if let Some(config) = &state.worker {
            return isolated::decompile_with_operations(
                self,
                annotations,
                options,
                config,
                Some((address, name)),
                context,
            );
        }
        let mut engine = self.build_decompiler_with_operations(
            options,
            annotations,
            context.operations,
            Some(address),
            context.admitted,
        )?;
        let thumb = self.binary.arch == rampage_arch::Arch::Arm
            && context::mode_at(&self.binary.target(), &self.analysis()?.program.code_modes, address);
        let code = engine.decompile(address, &name, thumb).map_err(native_decompile_error)?;
        if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ApiError::Unavailable("decompilation cancelled".into()));
        }
        let tokens = engine
            .tokens()
            .into_iter()
            .map(|token| DecompiledToken {
                text: token.text,
                kind: token.kind,
                address: token.address,
                span: token.span,
            })
            .collect();
        let mut structure = engine.structured_result().map_err(|error| ApiError::Unavailable(error.to_string()))?;
        crate::propagation::validate_replayed_targets(self, options, annotations, address, &structure)?;
        let (_, limitations) = crate::propagation::replay_hints(self, options, annotations, Some(address))?;
        crate::propagation::append_limitations(&mut structure, limitations);
        let variables = crate::variables::descriptors(&structure);
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        Ok(Decompilation {
            address,
            name,
            code,
            language_id: engine.language_id().to_owned(),
            tokens,
            recovery_status: structure.recovery_status(),
            structure,
            variables,
        })
    }
}
