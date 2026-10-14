use std::fmt::Write;
use std::sync::atomic::AtomicBool;

use rampage_decompiler::DecompilerOptions;
use rampage_decompiler::worker::{
    PROTOCOL_VERSION, WorkerCodeMode, WorkerConfig, WorkerFunction, WorkerMapping, WorkerOptions, WorkerRequest,
    run_supervised,
};

use super::{Decompilation, DecompiledToken, context, go_abi, image, symbols, types};
use crate::{ApiError, Project, annotations::Annotations};

pub(super) fn decompile(
    project: &Project,
    annotations: &Annotations,
    options: &DecompilerOptions,
    config: &WorkerConfig,
    function: Option<(u64, String)>,
    cancellation: &AtomicBool,
) -> Result<Decompilation, ApiError> {
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
    let go = go_abi::plan(project, annotations, options);
    operations.extend(types::plan(project, annotations, &go.types)?);
    operations.extend(go.prototypes);
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
    };
    check()?;
    let mut remaining = config.clone();
    remaining.timeout = config.timeout.saturating_sub(started.elapsed());
    let output = run_supervised(&request, &remaining, Some(cancellation))
        .map_err(|error| ApiError::Unavailable(error.to_string()))?;
    crate::debug_layout_import::validate_replay_source(project, annotations)?;
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
    Ok(Decompilation {
        address,
        name,
        code: output.text,
        language_id: output.language_id,
        tokens,
        recovery_status: structure.recovery_status(),
        structure,
    })
}
