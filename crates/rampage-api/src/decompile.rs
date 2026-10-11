//! C decompilation of a function, through the embedded Ghidra decompiler (`rampage-decompiler`). The decompiler
//! is built once per project over its executable segments and reused for every function.

mod context;
mod image;
mod isolated;
mod symbols;
mod types;

use rampage_decompiler::{Decompiler, DecompilerOptions, Platform};
use serde::Serialize;

use crate::{ApiError, Project};

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
}

fn serialize_structure<S: serde::Serializer>(
    structure: &rampage_decompiler::StructuredResult,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    fn addresses(value: &mut serde_json::Value, key: Option<&str>) {
        match value {
            serde_json::Value::Number(number)
                if matches!(key, Some("address" | "start" | "end" | "source" | "target" | "switch_address")) =>
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
    names: std::collections::BTreeMap<u64, String>,
    signatures: std::collections::BTreeMap<u64, String>,
    types: std::collections::BTreeMap<u64, String>,
    globals: std::collections::BTreeMap<u64, String>,
    pub(crate) worker: Option<rampage_decompiler::worker::WorkerConfig>,
}

pub(crate) fn default_options(binary: &rampage_loaders::Binary) -> DecompilerOptions {
    let platform = match binary.format {
        rampage_loaders::Format::Pe => Platform::Windows,
        rampage_loaders::Format::MachO => Platform::Darwin,
        rampage_loaders::Format::Elf | rampage_loaders::Format::Snapshot => Platform::Default,
    };
    let target = binary.target();
    let (platform, compiler) = binary.snapshot_target.as_ref().map_or((platform, None), |context| {
        let platform = match context.platform {
            rampage_loaders::snapshot::SnapshotPlatform::Default => Platform::Default,
            rampage_loaders::snapshot::SnapshotPlatform::Darwin => Platform::Darwin,
            rampage_loaders::snapshot::SnapshotPlatform::Windows => Platform::Windows,
        };
        (platform, context.compiler.clone())
    });
    DecompilerOptions {
        platform,
        compiler,
        arm_be8: binary.arch == rampage_arch::Arch::Arm && target.data_big_endian && !target.big_endian,
    }
}

impl Project {
    pub(crate) fn validate_annotation_snapshot(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        candidate: &crate::annotations::Annotations,
    ) -> Result<(), String> {
        if candidate.types().is_empty() && candidate.signatures().is_empty() && candidate.globals().is_empty() {
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
    /// Enables supervised child-process decompilation. No in-process fallback occurs when the worker fails.
    pub fn set_decompiler_worker(&self, config: Option<rampage_decompiler::worker::WorkerConfig>) {
        let mut state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        state.engine = None;
        state.worker = config;
    }
    /// Stores one address-bound C signature, including an optional calling convention such as __cdecl.
    pub fn set_signature(&self, address: u64, declaration: Option<&str>) -> Result<crate::EditResult, ApiError> {
        let address = if self.binary.import_slot(address).is_some() {
            address
        } else {
            self.function_containing(address)?.unwrap_or(address)
        };
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
            types::validate(value)?;
        }
        if field == Field::Signature
            && value.is_some()
            && !self.binary.is_code(address)
            && self.binary.import_slot(address).is_none()
        {
            return Err(ApiError::Invalid("signature address is neither code nor an import slot".to_owned()));
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        let value = value.map(str::to_owned);
        let changed = annotations
            .set_validated(field, address, value.clone(), |candidate| {
                self.validate_annotation_snapshot(&state, &options, candidate)
            })
            .map_err(ApiError::Invalid)?;
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
    }

    /// Decompiles the function containing `address` to C using bundled processor specifications.
    pub fn decompile(&self, address: u64) -> Result<Decompilation, ApiError> {
        self.decompile_cancellable(address, &std::sync::atomic::AtomicBool::new(false))
    }

    pub fn decompile_cancellable(
        &self,
        address: u64,
        cancellation: &std::sync::atomic::AtomicBool,
    ) -> Result<Decompilation, ApiError> {
        let start = self.function_containing(address)?.unwrap_or(address);
        if self.binary.code_from(start).is_none() {
            return Err(ApiError::Invalid("decompilation requires a file-backed code address".to_owned()));
        }
        let mut slot = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let annotations = self.annotations().snapshot();
        let name = self.function_name_in(&annotations, start);
        if let Some(config) = slot.worker.clone() {
            let options = slot.options.clone().unwrap_or_else(|| default_options(&self.binary));
            drop(slot);
            return isolated::decompile(self, &annotations, &options, &config, Some((start, name)), cancellation);
        }
        if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ApiError::Unavailable("decompilation cancelled".to_owned()));
        }
        if slot.names != *annotations.names() {
            slot.engine = None;
        }
        if slot.signatures != *annotations.signatures()
            || slot.types != *annotations.types()
            || slot.globals != *annotations.globals()
        {
            slot.engine = None;
        }
        if slot.engine.is_none() {
            let options = slot.options.clone().unwrap_or_else(|| default_options(&self.binary));
            slot.engine = Some(self.build_decompiler(&options, &annotations)?);
            slot.names = annotations.names().clone();
            slot.signatures = annotations.signatures().clone();
            slot.types = annotations.types().clone();
            slot.globals = annotations.globals().clone();
        }
        let decompiler = slot.engine.as_mut().expect("just built");
        let thumb = if self.binary.arch == rampage_arch::Arch::Arm {
            context::mode_at(&self.binary.target(), &self.analysis()?.program.code_modes, start)
        } else {
            false
        };
        let code =
            decompiler.decompile(start, &name, thumb).map_err(|error| ApiError::Unavailable(error.to_string()))?;
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
        let structure = decompiler.structured_result().map_err(|error| ApiError::Unavailable(error.to_string()))?;
        Ok(Decompilation {
            address: start,
            name,
            code,
            language_id: decompiler.language_id().to_owned(),
            tokens,
            recovery_status: structure.recovery_status(),
            structure,
        })
    }

    /// Builds a decompiler over the program's loadable segments and registers the names rampage knows, so calls
    /// render by name. Read-only segments are mapped read-only so strings and constant pointers fold into output.
    pub(crate) fn build_decompiler(
        &self,
        options: &DecompilerOptions,
        annotations: &crate::annotations::Annotations,
    ) -> Result<Decompiler, ApiError> {
        let binary = &self.binary;
        let regions = image::regions(binary)?;
        // A segment can hold more than code (a Mach-O __TEXT starts with headers), so require an executable
        // segment rather than one that begins at code.
        if !binary.segments.iter().any(|segment| segment.perms.execute && segment.file_size > 0) {
            return Err(ApiError::Unavailable("no executable segments to decompile".to_owned()));
        }
        let mut decompiler = Decompiler::open_with_options(binary.arch, binary.big_endian, &regions, options)
            .map_err(|error| ApiError::Unavailable(error.to_string()))?;
        if binary.arch == rampage_arch::Arch::Arm {
            let modes = context::arm_points(binary, &self.analysis()?.program.code_modes);
            decompiler.set_code_modes(&modes).map_err(|error| ApiError::Unavailable(error.to_string()))?;
        }

        let mut operations = symbols::plan(self, annotations)?;
        operations.extend(types::plan(self, annotations)?);
        symbols::apply(operations, &mut decompiler)?;
        Ok(decompiler)
    }
}
