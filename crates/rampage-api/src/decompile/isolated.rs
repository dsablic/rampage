use std::fmt::Write;
use std::sync::atomic::AtomicBool;

use rampage_decompiler::DecompilerOptions;
use rampage_decompiler::worker::{
    PROTOCOL_VERSION, WorkerCodeMode, WorkerConfig, WorkerFunction, WorkerMapping, WorkerOptions, WorkerRequest,
    run_supervised,
};

use super::{Decompilation, DecompiledToken, NativeDecompileContext, context, go_abi, image, symbols, types};
use crate::{ApiError, Project, annotations::Annotations};

struct TypeInspection<'a> {
    query: Option<rampage_decompiler::worker::TypeQuery>,
    declarations: &'a [(String, Option<u32>)],
    extra_operations: &'a [rampage_decompiler::worker::WorkerOperation],
    hint_context: Option<&'a std::collections::BTreeSet<u64>>,
}

pub(super) fn decompile(
    project: &Project,
    annotations: &Annotations,
    options: &DecompilerOptions,
    config: &WorkerConfig,
    function: Option<(u64, String)>,
    cancellation: &AtomicBool,
) -> Result<Decompilation, ApiError> {
    decompile_with_operations(
        project,
        annotations,
        options,
        config,
        function,
        NativeDecompileContext { cancellation: Some(cancellation), ..Default::default() },
    )
}

pub(super) fn decompile_with_operations(
    project: &Project,
    annotations: &Annotations,
    options: &DecompilerOptions,
    config: &WorkerConfig,
    function: Option<(u64, String)>,
    context: NativeDecompileContext<'_>,
) -> Result<Decompilation, ApiError> {
    let never_cancelled = AtomicBool::new(false);
    let cancellation = context.cancellation.unwrap_or(&never_cancelled);
    let validate_only = function.is_none();
    let (address, name) = function.clone().unwrap_or_default();
    let output = run(
        project,
        annotations,
        options,
        config,
        function,
        cancellation,
        TypeInspection {
            query: None,
            declarations: &[],
            extra_operations: context.operations,
            hint_context: context.admitted,
        },
    )?;
    let mut result = finish_output(output, address, name, validate_only)?;
    if !validate_only {
        crate::propagation::validate_replayed_targets(project, options, annotations, address, &result.structure)?;
    }
    let (_, limitations) = crate::propagation::replay_hints(project, options, annotations, Some(address))?;
    crate::propagation::append_limitations(&mut result.structure, limitations);
    result.recovery_status = result.structure.recovery_status();
    Ok(result)
}

pub(crate) fn query_types(
    project: &Project,
    annotations: &Annotations,
    options: &DecompilerOptions,
    config: &WorkerConfig,
    query: rampage_decompiler::worker::TypeQuery,
    declarations: &[(String, Option<u32>)],
) -> Result<rampage_decompiler::worker::WorkerOutput, ApiError> {
    query_types_cancellable(project, annotations, options, config, query, declarations, &AtomicBool::new(false))
}

pub(crate) fn query_types_cancellable(
    project: &Project,
    annotations: &Annotations,
    options: &DecompilerOptions,
    config: &WorkerConfig,
    query: rampage_decompiler::worker::TypeQuery,
    declarations: &[(String, Option<u32>)],
    cancellation: &AtomicBool,
) -> Result<rampage_decompiler::worker::WorkerOutput, ApiError> {
    run(
        project,
        annotations,
        options,
        config,
        None,
        cancellation,
        TypeInspection { query: Some(query), declarations, extra_operations: &[], hint_context: None },
    )
}

fn run(
    project: &Project,
    annotations: &Annotations,
    options: &DecompilerOptions,
    config: &WorkerConfig,
    function: Option<(u64, String)>,
    cancellation: &AtomicBool,
    inspection: TypeInspection<'_>,
) -> Result<rampage_decompiler::worker::WorkerOutput, ApiError> {
    let TypeInspection { query: type_query, declarations, extra_operations, hint_context } = inspection;
    crate::debug_layout_import::validate_replay_source(project, annotations)?;
    let validate_only = function.is_none();
    let (address, name) = function.unwrap_or_default();
    let started = std::time::Instant::now();
    let check = || {
        if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ApiError::Unavailable("decompilation cancelled".to_owned()));
        }
        if started.elapsed() >= config.timeout {
            return Err(ApiError::Unavailable("decompilation timed out while preparing worker input".to_owned()));
        }
        Ok(())
    };
    check()?;
    let binary = &project.binary;
    let mappings = image::regions(binary)?
        .iter()
        .map(|region| {
            check()?;
            let mut hex_bytes = String::with_capacity(region.bytes.len() * 2);
            for (index, byte) in region.bytes.iter().enumerate() {
                if index.is_multiple_of(4096) {
                    check()?;
                }
                write!(hex_bytes, "{byte:02x}").expect("write hex");
            }
            Ok::<_, ApiError>(WorkerMapping {
                base: region.base,
                hex_bytes,
                size: region.size,
                readable: region.readable,
                writable: region.writable,
                executable: region.executable,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let modes = if binary.arch == rampage_arch::Arch::Arm {
        context::arm_points(binary, &project.analysis()?.program.code_modes)
    } else {
        Vec::new()
    };
    let thumb = binary.arch == rampage_arch::Arch::Arm
        && context::mode_at(&binary.target(), &project.analysis()?.program.code_modes, address);
    crate::debug_layout_import::validate_replay_source(project, annotations)?;
    let mut operations = symbols::plan(project, annotations)?;
    if type_query.is_none() && symbols::requires_import_context(&operations) {
        let context = query_types_cancellable(
            project,
            annotations,
            options,
            config,
            rampage_decompiler::worker::TypeQuery::Inventory,
            &[],
            cancellation,
        )?;
        symbols::specialize_imports(
            annotations,
            options,
            &context.language_id,
            rampage_decompiler::DataOrganization {
                pointer: context.data_organization.pointer,
                int: context.data_organization.int,
                long: context.data_organization.long,
            },
            &mut operations,
        )?;
    } else if type_query.is_some() {
        // A model-only child query must not install an OS-specific fallback before its context is known.
        operations.retain(|operation| {
            !matches!(operation,
            rampage_decompiler::worker::WorkerOperation::RuntimePrototype { name, .. }
                if matches!(name.trim_start_matches('_'), "recv" | "CreateFileW")
                    || name.starts_with("_recv@") || name.starts_with("_CreateFileW@"))
        });
    }
    let go = go_abi::plan(project, annotations, options);
    operations.extend(types::plan(project, annotations, &go.types)?);
    operations.extend(go.prototypes);
    operations.extend(crate::variables::plan(project, annotations, None)?);
    operations.extend(if let Some(context) = hint_context {
        crate::propagation::hint_operations_in_context(project, options, annotations, context)?
    } else {
        crate::propagation::hint_operations(project, options, annotations, (!validate_only).then_some(address))?
    });
    operations.extend_from_slice(extra_operations);
    operations.extend(declarations.iter().map(|(declarations, packing)| {
        rampage_decompiler::worker::WorkerOperation::TypeLibrary {
            declarations: declarations.clone(),
            packing: *packing,
        }
    }));
    let querying_types = type_query.is_some();
    let request = WorkerRequest {
        version: PROTOCOL_VERSION,
        arch: binary.arch.to_string(),
        big_endian: binary.big_endian,
        options: WorkerOptions {
            platform: match options.platform {
                rampage_decompiler::Platform::Default => "default",
                rampage_decompiler::Platform::Windows => "windows",
                rampage_decompiler::Platform::Darwin => "darwin",
            }
            .to_owned(),
            compiler: options.compiler.clone(),
            arm_be8: options.arm_be8,
        },
        mappings,
        code_modes: modes.into_iter().map(|(address, thumb)| WorkerCodeMode { address, thumb }).collect(),
        operations,
        decompile: WorkerFunction { address, name: name.clone(), thumb },
        tokens: true,
        validate_only,
        type_query,
    };
    check()?;
    let mut remaining = config.clone();
    remaining.timeout = config.timeout.saturating_sub(started.elapsed());
    let output = run_supervised(&request, &remaining, Some(cancellation)).map_err(|error| match error {
        rampage_decompiler::worker::WorkerError::Decompile(message)
            if super::hint_context_error(&message).is_some() =>
        {
            super::hint_context_error(&message).expect("classified native context refusal")
        }
        rampage_decompiler::worker::WorkerError::Decompile(message) if querying_types => ApiError::Invalid(message),
        error => ApiError::Unavailable(error.to_string()),
    })?;
    crate::type_library::validate_profile_replay(
        annotations,
        options,
        rampage_decompiler::DataOrganization {
            pointer: output.data_organization.pointer,
            int: output.data_organization.int,
            long: output.data_organization.long,
        },
        &output.language_id,
    )?;
    crate::debug_layout_import::validate_replay_source(project, annotations)?;
    Ok(output)
}

pub(super) fn finish_output(
    output: rampage_decompiler::worker::WorkerOutput,
    address: u64,
    name: String,
    validate_only: bool,
) -> Result<Decompilation, ApiError> {
    let tokens = output
        .tokens
        .unwrap_or_default()
        .into_iter()
        .map(|token| DecompiledToken { text: token.text, kind: token.kind, address: token.address, span: token.span })
        .collect();
    let structure = if validate_only {
        rampage_decompiler::StructuredResult::empty()
    } else {
        output.structure.ok_or_else(|| ApiError::Unavailable("worker omitted structured result".to_owned()))?
    };
    let variables = crate::variables::descriptors(&structure);
    Ok(Decompilation {
        address,
        name,
        code: output.text,
        language_id: output.language_id,
        tokens,
        recovery_status: structure.recovery_status(),
        structure,
        variables,
    })
}
