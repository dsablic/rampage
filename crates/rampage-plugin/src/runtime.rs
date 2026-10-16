use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use wasmtime::component::types::{ComponentExtern, ComponentItem, Type};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, OutOfMemory, Store, StoreLimitsBuilder, Trap, WasmFeatures};

use crate::{
    COMPONENT_INTERFACE, MAX_INSTANCES, MAX_MEMORIES, MAX_MEMORY_BYTES, MAX_OUTPUT_BYTES, MAX_TABLE_ELEMENTS,
    MAX_TABLES, MAX_WASM_STACK, PluginError,
};

pub(crate) fn execute(bytes: &[u8], input: &[u8], fuel: u64, timeout: Duration) -> Result<Vec<u8>, PluginError> {
    let mut config = Config::new();
    config.consume_fuel(true).epoch_interruption(true).max_wasm_stack(MAX_WASM_STACK);
    config.wasm_backtrace_max_frames(None);
    config.memory_reservation(0).memory_reservation_for_growth(0).memory_guard_size(64 * 1024);
    config.cranelift_opt_level(wasmtime::OptLevel::None);
    config.wasm_features(WasmFeatures::all(), false);
    config.wasm_features(
        WasmFeatures::WASM2.difference(WasmFeatures::GC_TYPES)
            | WasmFeatures::COMPONENT_MODEL
            | WasmFeatures::MULTI_MEMORY,
        true,
    );
    let engine = Engine::new(&config).map_err(|_| PluginError::Configuration)?;
    let component = Component::new(&engine, bytes)
        .map_err(|error| if error.is::<OutOfMemory>() { PluginError::Resource } else { PluginError::Compile })?;
    check_abi(&engine, &component)?;
    let linker = Linker::new(&engine);
    let instance_pre = linker.instantiate_pre(&component).map_err(|_| PluginError::Abi)?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(MAX_MEMORY_BYTES)
        .memories(MAX_MEMORIES)
        .table_elements(MAX_TABLE_ELEMENTS)
        .tables(MAX_TABLES)
        .instances(MAX_INSTANCES)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(&engine, limits);
    store.limiter(|limits| limits);
    store.set_fuel(fuel).map_err(|_| PluginError::Configuration)?;
    store.epoch_deadline_trap();
    store.set_epoch_deadline(1);
    let started = Instant::now();
    thread::scope(|scope| {
        let (stop, wait) = mpsc::channel();
        let ticker_engine = engine.clone();
        let ticker = thread::Builder::new()
            .name("plugin-epoch".to_owned())
            .spawn_scoped(scope, move || {
                let remaining = timeout.saturating_sub(started.elapsed());
                if matches!(wait.recv_timeout(remaining), Err(mpsc::RecvTimeoutError::Timeout)) {
                    ticker_engine.increment_epoch();
                }
            })
            .map_err(|_| PluginError::Resource)?;
        let result = (|| {
            let instance = instance_pre.instantiate(&mut store).map_err(classify_execution)?;
            let interface = instance.get_export_index(&mut store, None, COMPONENT_INTERFACE).ok_or(PluginError::Abi)?;
            let run_index = instance.get_export_index(&mut store, Some(&interface), "run").ok_or(PluginError::Abi)?;
            let output_index =
                instance.get_export_index(&mut store, Some(&interface), "output").ok_or(PluginError::Abi)?;
            let run =
                instance.get_typed_func::<(&[u8],), (u32,)>(&mut store, &run_index).map_err(|_| PluginError::Abi)?;
            let output = instance
                .get_typed_func::<(u32,), ((u64, u64, u64, u64),)>(&mut store, &output_index)
                .map_err(|_| PluginError::Abi)?;
            let (length,) = run.call(&mut store, (input,)).map_err(classify_execution)?;
            let length = length as usize;
            if length > MAX_OUTPUT_BYTES {
                return Err(PluginError::OutputTooLarge);
            }
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length).map_err(|_| PluginError::Resource)?;
            for offset in (0..length).step_by(32) {
                check_execution_deadline(started, timeout)?;
                let ((a, b, c, d),) = output.call(&mut store, (offset as u32,)).map_err(classify_execution)?;
                for word in [a, b, c, d] {
                    let remaining = (length - bytes.len()).min(8);
                    bytes.extend_from_slice(&word.to_le_bytes()[..remaining]);
                }
            }
            check_execution_deadline(started, timeout)?;
            Ok(bytes)
        })();
        let _ = stop.send(());
        ticker.join().map_err(|_| PluginError::Worker)?;
        result
    })
}

fn check_execution_deadline(started: Instant, timeout: Duration) -> Result<(), PluginError> {
    if started.elapsed() >= timeout { Err(PluginError::ExecutionDeadline) } else { Ok(()) }
}

fn classify_execution(error: wasmtime::Error) -> PluginError {
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => PluginError::Fuel,
        Some(Trap::Interrupt) => PluginError::ExecutionDeadline,
        Some(Trap::StackOverflow) => PluginError::Resource,
        Some(_) => PluginError::Trap,
        None if error.is::<OutOfMemory>() => PluginError::Resource,
        None => PluginError::Resource,
    }
}

fn check_abi(engine: &Engine, component: &Component) -> Result<(), PluginError> {
    let ty = component.component_type();
    if ty.imports(engine).next().is_some() {
        return Err(PluginError::Abi);
    }
    let mut exports = ty.exports(engine);
    let Some((name, export)) = exports.next() else {
        return Err(PluginError::Abi);
    };
    let ComponentItem::ComponentInstance(interface) = plain_export(export)? else {
        return Err(PluginError::Abi);
    };
    if name != COMPONENT_INTERFACE || exports.next().is_some() || interface.exports(engine).len() != 2 {
        return Err(PluginError::Abi);
    }
    let Some(run) = interface.get_export(engine, "run") else {
        return Err(PluginError::Abi);
    };
    let ComponentItem::ComponentFunc(run) = plain_export(run)? else {
        return Err(PluginError::Abi);
    };
    let Some(output) = interface.get_export(engine, "output") else {
        return Err(PluginError::Abi);
    };
    let ComponentItem::ComponentFunc(output) = plain_export(output)? else {
        return Err(PluginError::Abi);
    };
    let mut run_params = run.params();
    let mut run_results = run.results();
    let mut output_params = output.params();
    let mut output_results = output.results();
    if run.async_()
        || output.async_()
        || run_params.len() != 1
        || !matches!(run_params.next(), Some(("input", Type::List(list))) if list.ty() == Type::U8)
        || run_results.len() != 1
        || run_results.next() != Some(Type::U32)
        || output_params.len() != 1
        || output_params.next() != Some(("offset", Type::U32))
        || output_results.len() != 1
    {
        return Err(PluginError::Abi);
    }
    let Some(Type::Tuple(tuple)) = output_results.next() else {
        return Err(PluginError::Abi);
    };
    if tuple.types().len() != 4 || tuple.types().any(|ty| ty != Type::U64) {
        return Err(PluginError::Abi);
    }
    Ok(())
}

fn plain_export(export: ComponentExtern<'_>) -> Result<ComponentItem, PluginError> {
    if export.implements.is_some() || export.external_id.is_some() {
        return Err(PluginError::Abi);
    }
    Ok(export.ty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_compiled_component_types_reject_missing_exports_and_ambient_imports() {
        let config = Config::new();
        let engine = Engine::new(&config).expect("test engine");
        let empty = Component::new(&engine, b"\0asm\x0d\0\x01\0").expect("valid empty binary component");
        assert_eq!(check_abi(&engine, &empty), Err(PluginError::Abi));
        let imported = b"\0asm\x0d\0\x01\0\x07\x05\x01\x40\0\x01\0\x0a\x06\x01\0\x01f\x01\0";
        let component = Component::new(&engine, imported).expect("valid imported-function component");
        assert_eq!(check_abi(&engine, &component), Err(PluginError::Abi));
    }
}
