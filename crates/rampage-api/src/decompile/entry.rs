use std::fmt::Write;
use std::sync::TryLockError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rampage_decompiler::worker::{
    PROTOCOL_VERSION, WorkerFunction, WorkerMapping, WorkerOptions, WorkerRequest, run_supervised,
};
use rampage_decompiler::{Decompiler, Platform};
use serde::Serialize;

use super::{
    Decompilation, DecompiledToken, DecompilerConfigurationRevision, default_options, entry_plan, go_abi, image,
    isolated, symbols, types,
};
use crate::{ApiError, Project, debug_layout_import};

pub use super::entry_plan::{EntryOrigin as DecompileEntryOrigin, EntryPlanCounts as EntryContextCounts};

const MAX_ENTRY_IMAGE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryValidation {
    MetadataBacked,
    AnalystAsserted,
}

#[derive(Debug, Clone, Copy)]
pub struct DecompileEntryRequest {
    pub address: u64,
    pub validation: EntryValidation,
}

#[derive(Debug, Serialize)]
pub struct EntryDecompilation {
    #[serde(flatten)]
    pub decompilation: Decompilation,
    pub context: EntryDecompilationContext,
}

#[derive(Debug, Serialize)]
pub struct EntryDecompilationContext {
    pub scope: &'static str,
    pub validation: EntryValidation,
    pub origins: Vec<DecompileEntryOrigin>,
    pub inside_symbol_extent: bool,
    pub full_image_mapping: bool,
    pub mapped_backing_checked: bool,
    pub mapped_regions: usize,
    pub mapped_backed_bytes: usize,
    pub counts: EntryContextCounts,
    pub generated_dependency_types: usize,
    pub replay_operations: usize,
    pub sample: rampage_analysis::entry_audit::EntryAudit,
    pub omissions: Vec<String>,
    pub execution: &'static str,
    pub timings: EntryPreparationTimings,
    /// Process-local binding of the settings actually captured for this request; never a serialized receipt.
    #[serde(skip)]
    pub configuration_revision: DecompilerConfigurationRevision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryPreparationPhase {
    Configuration,
    Metadata,
    Replay,
    Mapping,
    WorkerSerialization,
    WorkerExecution,
    NativeInitialization,
    NativeReplay,
    NativeExecution,
    ResultValidation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EntryPreparationProgress {
    pub phase: EntryPreparationPhase,
    pub elapsed_ms: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct EntryPreparationTimings {
    pub configuration_ms: u64,
    pub metadata_ms: u64,
    pub replay_ms: u64,
    pub mapping_ms: u64,
    pub execution_ms: u64,
    pub total_ms: u64,
}

fn elapsed(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn source(project: &Project) -> Result<bool, ApiError> {
    project
        .binary
        .validate_available_backing_source()
        .map_err(|error| ApiError::Unavailable(format!("exact-entry source: {error}")))
}

impl Project {
    /// Decompiles the exact requested entry with bounded local context and the complete mapped image.
    /// Metadata declarations or an analyst assertion are not proof of a complete, valid function boundary.
    pub fn decompile_entry(&self, request: &DecompileEntryRequest) -> Result<EntryDecompilation, ApiError> {
        self.decompile_entry_cancellable(request, &AtomicBool::new(false))
    }

    pub fn decompile_entry_cancellable(
        &self,
        request: &DecompileEntryRequest,
        cancellation: &AtomicBool,
    ) -> Result<EntryDecompilation, ApiError> {
        self.decompile_entry_with_progress(request, cancellation, |_| {})
    }

    /// Reports actual host-side phase boundaries on the calling thread, outside Project locks.
    /// Observer time counts toward the worker deadline. Native FFI calls remain cooperatively cancellable.
    pub fn decompile_entry_with_progress(
        &self,
        request: &DecompileEntryRequest,
        cancellation: &AtomicBool,
        progress: impl FnMut(EntryPreparationProgress),
    ) -> Result<EntryDecompilation, ApiError> {
        self.decompile_entry_observed(request, cancellation, progress, None)
    }

    /// Opt-in supervisor observations, delivered even when the worker fails. Native-inline calls emit none.
    /// Supervisor offsets exclude these observers and are not child-internal native initialization timings.
    pub fn decompile_entry_measured(
        &self,
        request: &DecompileEntryRequest,
        cancellation: &AtomicBool,
        progress: impl FnMut(EntryPreparationProgress),
        mut supervisor: impl FnMut(rampage_decompiler::worker::SupervisedMetrics),
    ) -> Result<EntryDecompilation, ApiError> {
        self.decompile_entry_observed(request, cancellation, progress, Some(&mut supervisor))
    }

    fn decompile_entry_observed(
        &self,
        request: &DecompileEntryRequest,
        cancellation: &AtomicBool,
        mut progress: impl FnMut(EntryPreparationProgress),
        mut supervisor: Option<&mut dyn FnMut(rampage_decompiler::worker::SupervisedMetrics)>,
    ) -> Result<EntryDecompilation, ApiError> {
        let started = Instant::now();
        if cancellation.load(Ordering::Relaxed) {
            return Err(ApiError::Unavailable("exact-entry cancelled before configuration".to_owned()));
        }
        if !matches!(
            self.binary.arch,
            rampage_arch::Arch::X86 | rampage_arch::Arch::X86_64 | rampage_arch::Arch::Aarch64
        ) || self.binary.big_endian
        {
            return Err(ApiError::Unavailable(
                "exact-entry decompilation supports little-endian x86, x86-64 and AArch64 only".to_owned(),
            ));
        }
        progress(EntryPreparationProgress {
            phase: EntryPreparationPhase::Configuration,
            elapsed_ms: elapsed(started),
        });
        if cancellation.load(Ordering::Relaxed) {
            return Err(ApiError::Unavailable("exact-entry cancelled during configuration".to_owned()));
        }
        source(self)?;
        let (options, worker, configuration_revision) = {
            let state = match self.decompiler.try_lock() {
                Ok(state) => state,
                Err(TryLockError::Poisoned(error)) => error.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    return Err(ApiError::Unavailable("exact-entry decompiler configuration is busy".to_owned()));
                }
            };
            (
                state.options.clone().unwrap_or_else(|| default_options(&self.binary)),
                state.worker.clone(),
                DecompilerConfigurationRevision(std::sync::Arc::clone(&state.configuration_revision)),
            )
        };
        let check = |stage: &'static str| {
            if cancellation.load(Ordering::Relaxed) {
                return Err(ApiError::Unavailable(format!("exact-entry cancelled during {stage}")));
            }
            if worker.as_ref().is_some_and(|config| started.elapsed() >= config.timeout) {
                return Err(ApiError::Unavailable(format!("exact-entry timed out during {stage}")));
            }
            Ok(())
        };
        let mut report_phase = |phase| -> Result<(), ApiError> {
            check("phase transition")?;
            progress(EntryPreparationProgress { phase, elapsed_ms: elapsed(started) });
            check("phase observer")?;
            source(self)?;
            Ok(())
        };
        check("annotation snapshot")?;
        let annotations = {
            let current = match self.annotations.try_read() {
                Ok(current) => current,
                Err(TryLockError::Poisoned(error)) => error.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    return Err(ApiError::Unavailable("exact-entry annotations are busy".to_owned()));
                }
            };
            current.preflight_checked().map_err(ApiError::Invalid)?;
            debug_layout_import::validate_replay_budget(&current)?;
            current.snapshot()
        };
        if annotations.has_checked_layouts() {
            self.check_layout_options(&options)?;
        }
        let mapped_backing_checked = source(self)?;
        debug_layout_import::validate_entry_replay_source(self, &annotations)?;
        let mut timings = EntryPreparationTimings { configuration_ms: elapsed(started), ..Default::default() };

        let stage = Instant::now();
        report_phase(EntryPreparationPhase::Metadata)?;
        let plan = entry_plan::prepare(self, &annotations, request, &check)?;
        let sample = self.entry_diagnostics(Some(request.address))?;
        check("entry evidence")?;
        timings.metadata_ms = elapsed(stage);

        let stage = Instant::now();
        report_phase(EntryPreparationPhase::Replay)?;
        let generated = go_abi::entry_types(self, &annotations, &options)?;
        let replay = types::plan_entry(self, &annotations, &generated, &plan.stub_targets)?;
        let replay_operations = replay.len();
        let generated_dependency_types = generated.len();
        let mut operations = plan.operations;
        operations.extend(replay);
        check("declaration replay preparation")?;
        debug_layout_import::validate_entry_replay_source(self, &annotations)?;
        timings.replay_ms = elapsed(stage);

        let stage = Instant::now();
        report_phase(EntryPreparationPhase::Mapping)?;
        if self.binary.image_bytes().len() > MAX_ENTRY_IMAGE_BYTES {
            return Err(ApiError::Invalid("exact-entry selected image exceeds the 128 MiB byte budget".to_owned()));
        }
        source(self)?;
        let regions = image::regions(&self.binary)?;
        let mut mapped_backed_bytes = 0usize;
        for region in &regions {
            check("full-image mapping preparation")?;
            mapped_backed_bytes = mapped_backed_bytes
                .checked_add(region.bytes.len())
                .filter(|&bytes| bytes <= MAX_ENTRY_IMAGE_BYTES)
                .ok_or_else(|| ApiError::Invalid("exact-entry aggregate backed mapping budget exceeded".to_owned()))?;
        }
        source(self)?;
        timings.mapping_ms = elapsed(stage);

        let stage = Instant::now();
        let (decompilation, execution) = if let Some(config) = worker.as_ref() {
            report_phase(EntryPreparationPhase::WorkerSerialization)?;
            let mut mappings = Vec::with_capacity(regions.len());
            for region in &regions {
                let mut hex_bytes = String::with_capacity(region.bytes.len() * 2);
                for (index, byte) in region.bytes.iter().enumerate() {
                    if index.is_multiple_of(4096) {
                        check("worker image serialization")?;
                    }
                    write!(hex_bytes, "{byte:02x}").expect("write bounded hex");
                }
                mappings.push(WorkerMapping {
                    base: region.base,
                    hex_bytes,
                    size: region.size,
                    readable: region.readable,
                    writable: region.writable,
                    executable: region.executable,
                });
            }
            let request = WorkerRequest {
                version: PROTOCOL_VERSION,
                arch: self.binary.arch.to_string(),
                big_endian: self.binary.big_endian,
                options: WorkerOptions {
                    platform: match options.platform {
                        Platform::Default => "default",
                        Platform::Darwin => "darwin",
                        Platform::Windows => "windows",
                    }
                    .to_owned(),
                    compiler: options.compiler.clone(),
                    arm_be8: options.arm_be8,
                },
                mappings,
                code_modes: Vec::new(),
                operations,
                decompile: WorkerFunction { address: plan.address, name: plan.name.clone(), thumb: false },
                tokens: true,
                validate_only: false,
            };
            report_phase(EntryPreparationPhase::WorkerExecution)?;
            check("worker dispatch")?;
            let mut remaining = config.clone();
            remaining.timeout = remaining.timeout.saturating_sub(started.elapsed());
            let output = if let Some(observer) = &mut supervisor {
                let observed =
                    rampage_decompiler::worker::run_supervised_measured(&request, &remaining, Some(cancellation));
                observer(observed.metrics);
                observed.result
            } else {
                run_supervised(&request, &remaining, Some(cancellation))
            }
            .map_err(|error| ApiError::Unavailable(format!("exact-entry worker: {error}")))?;
            check("supervisor observer")?;
            source(self)?;
            (isolated::finish_output(output, plan.address, plan.name, false)?, "supervised_worker")
        } else {
            report_phase(EntryPreparationPhase::NativeInitialization)?;
            check("native initialization")?;
            let mut engine =
                Decompiler::open_with_options(self.binary.arch, self.binary.big_endian, &regions, &options)
                    .map_err(|error| ApiError::Unavailable(format!("exact-entry native initialization: {error}")))?;
            report_phase(EntryPreparationPhase::NativeReplay)?;
            check("native declaration replay")?;
            symbols::apply(operations, &mut engine)?;
            report_phase(EntryPreparationPhase::NativeExecution)?;
            check("native execution")?;
            let code = engine
                .decompile(plan.address, &plan.name, false)
                .map_err(|error| ApiError::Unavailable(format!("exact-entry native execution: {error}")))?;
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
            let structure = engine.structured_result().map_err(|error| ApiError::Unavailable(error.to_string()))?;
            let result = Decompilation {
                address: plan.address,
                name: plan.name,
                code,
                language_id: engine.language_id().to_owned(),
                tokens,
                recovery_status: structure.recovery_status(),
                structure,
            };
            (result, "in_process_native")
        };
        report_phase(EntryPreparationPhase::ResultValidation)?;
        check("result validation")?;
        debug_layout_import::validate_entry_replay_source(self, &annotations)?;
        source(self)?;
        check("completed result validation")?;
        timings.execution_ms = elapsed(stage);
        timings.total_ms = elapsed(started);
        let mut omissions = plan.omissions;
        omissions.extend([
            "No whole-program containing-function resolution or learned mode context.".to_owned(),
            "No whole-program Go result/callee inference; only actual declarations and canonical dependencies replayed."
                .to_owned(),
            concat!("The local context walk is not a complete function, ",
                "call graph or proof of instruction boundaries.").to_owned(),
            "In-process native initialization/execution is not forcibly interruptible; cancellation is cooperative."
                .to_owned(),
        ]);
        Ok(EntryDecompilation {
            decompilation,
            context: EntryDecompilationContext {
                scope: "exact_entry",
                validation: request.validation,
                origins: plan.origins,
                inside_symbol_extent: plan.inside_symbol_extent,
                full_image_mapping: true,
                mapped_backing_checked,
                mapped_regions: regions.len(),
                mapped_backed_bytes,
                counts: plan.counts,
                generated_dependency_types,
                replay_operations,
                sample,
                omissions,
                execution,
                timings,
                configuration_revision,
            },
        })
    }
}

#[cfg(test)]
#[path = "entry_tests.rs"]
mod tests;
