use std::sync::atomic::AtomicBool;

use rampage_decompiler::worker::{ByteCheckpoint, SupervisedMetrics, WorkerConfig, run_supervised_bytes_checkpointed};

use crate::PluginError;

/// The component call boundary containing an active Wasm activation. Canonical lowering or allocation may
/// execute Wasm here; this does not assert entry into the guest's source-language function body or loop.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestCall {
    Run,
    Output,
}

impl From<GuestCall> for ByteCheckpoint {
    fn from(call: GuestCall) -> Self {
        match call {
            GuestCall::Run => Self::Run,
            GuestCall::Output => Self::Output,
        }
    }
}

impl From<ByteCheckpoint> for GuestCall {
    fn from(checkpoint: ByteCheckpoint) -> Self {
        match checkpoint {
            ByteCheckpoint::Run => Self::Run,
            ByteCheckpoint::Output => Self::Output,
        }
    }
}

/// Synchronous trusted observations, never guest text. The guest-active observer must set the supplied
/// cancellation flag and return promptly. It must not wait for the parked execution to finish.
/// Parking/observation is opt-in instrumentation governed by the outer process budget, not the execution
/// timeout's return bound. A parent observer cannot be interrupted while it blocks the supervising thread.
#[doc(hidden)]
#[derive(Debug)]
pub enum PluginObservation<'a> {
    GuestActive(GuestCall),
    /// Emitted after supervision returns (including cleanup and scoped I/O thread joining when spawned),
    /// with the execution permit still held. Emitted even on cancellation; inspect the metrics rather than
    /// inferring cleanup success from Cancelled. Observer panics unwind rather than producing a report.
    SupervisionFinished(&'a SupervisedMetrics),
}

/// No metrics means execution failed before entering byte supervision. Existing cleanup failures retain
/// their primary-error precedence; this probe does not introduce admission quarantine after failed cleanup.
#[doc(hidden)]
#[derive(Debug)]
pub struct CheckpointedPluginRun {
    pub result: Result<Vec<u8>, PluginError>,
    pub metrics: Option<SupervisedMetrics>,
}

pub(crate) struct CheckpointObserver<'a> {
    pub(crate) cancellation: &'a AtomicBool,
    pub(crate) call: GuestCall,
    pub(crate) observer: &'a mut dyn FnMut(PluginObservation<'_>),
    pub(crate) metrics: Option<SupervisedMetrics>,
}

impl CheckpointObserver<'_> {
    pub(crate) fn supervise(&mut self, bytes: Vec<u8>, config: &WorkerConfig) -> Result<Vec<u8>, PluginError> {
        let observer = &mut *self.observer;
        let run =
            run_supervised_bytes_checkpointed(bytes, config, self.cancellation, self.call.into(), &mut |checkpoint| {
                observer(PluginObservation::GuestActive(checkpoint.into()))
            });
        observer(PluginObservation::SupervisionFinished(&run.metrics));
        self.metrics = Some(run.metrics);
        run.result.map_err(PluginError::from)
    }
}
